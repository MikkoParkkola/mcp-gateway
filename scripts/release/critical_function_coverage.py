#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade each Critical function's own line coverage (MIK-7324.COV.3).

Reads the function inventory (docs/release/v4.0.0-critical-functions.tsv) and
an lcov report from `cargo llvm-cov report --lcov`. A function's lines are the
lcov `DA:` records from its `fn` line to the brace that closes its body; its
coverage is the share of those with a non-zero count.

Exit status: 0 when every Critical row clears the floor, 1 otherwise. A row
whose function is gone, or whose body has no `DA:` record (compiled out on
this platform), fails unless `--unmeasured report` is given, which lists it
without failing: a Linux run cannot grade a Windows-only function.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

FLOOR = 95.0


def strip_literals(line):
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])'", "''", line)
    return line.split("//", 1)[0]


def body_range(lines, start):
    """1-based inclusive range from the `fn` line to its closing brace."""
    depth, seen = 0, False
    for i in range(start - 1, len(lines)):
        code = strip_literals(lines[i])
        if not seen and ";" in code and "{" not in code:
            return start, i + 1
        depth += code.count("{") - code.count("}")
        seen = seen or "{" in code
        if seen and depth <= 0:
            return start, i + 1
    return start, len(lines)


def fn_line(lines, name, occurrence):
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    hits = [i + 1 for i, line in enumerate(lines) if pattern.search(line)]
    return hits[occurrence - 1] if len(hits) >= occurrence else None


def read_lcov(path):
    hits, current = {}, None
    for raw in Path(path).read_text().splitlines():
        if raw.startswith("SF:"):
            current = "src/" + raw[3:].replace("\\", "/").split("/src/", 1)[-1]
            hits.setdefault(current, {})
        elif raw.startswith("DA:") and current:
            number, count = raw[3:].split(",")[:2]
            line = int(number)
            hits[current][line] = hits[current].get(line, 0) + int(count)
    return hits


def read_inventory(path):
    rows = [line for line in Path(path).read_text().splitlines() if not line.startswith("#")]
    return list(csv.DictReader(rows, delimiter="\t"))


def grade(root, inventory, lcov):
    hits = read_lcov(lcov)
    results = []
    for row in read_inventory(inventory):
        if row["tier"] != "critical":
            continue
        source = Path(root) / row["path"]
        lines = source.read_text().splitlines() if source.exists() else []
        start = fn_line(lines, row["fn"], int(row["occurrence"]))
        if start is None:
            results.append(("MISSING", row, None, None, []))
            continue
        lo, hi = body_range(lines, start)
        counts = {n: c for n, c in hits.get(row["path"], {}).items() if lo <= n <= hi}
        if not counts:
            results.append(("UNMEASURED", row, lo, hi, []))
            continue
        covered = sum(1 for c in counts.values() if c > 0)
        missed = sorted(n for n, c in counts.items() if c == 0)
        pct = 100.0 * covered / len(counts)
        status = "ok" if pct >= FLOOR else "BELOW"
        results.append((status, row, lo, hi, missed, covered, len(counts), pct))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--inventory", default="docs/release/v4.0.0-critical-functions.tsv")
    parser.add_argument("--lcov", required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--unmeasured", choices=["fail", "report"], default="fail")
    args = parser.parse_args(argv)

    failed = 0
    for result in grade(args.root, args.inventory, args.lcov):
        status, row = result[0], result[1]
        where = f"{row['path']}:{row['fn']}#{row['occurrence']}"
        if status in ("ok", "BELOW"):
            _, _, lo, hi, missed, covered, total, pct = result
            print(f"{status}\t{pct:6.2f}%\t{covered}/{total}\t{where}\tlines {lo}-{hi}\tmissed={missed}")
            failed += status == "BELOW"
        else:
            print(f"{status}\t-\t-\t{where}")
            failed += status == "MISSING" or args.unmeasured == "fail"
    print(f"critical rows failing: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
