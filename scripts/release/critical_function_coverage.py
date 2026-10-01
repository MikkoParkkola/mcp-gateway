#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade each Critical function's own line coverage (MIK-7324.COV.3).

Reads the function inventory (docs/release/v4.0.0-critical-functions.tsv) and
one or more lcov reports from `cargo llvm-cov report --lcov`. A function's
lines are the `DA:` records from its `fn` line to the brace that closes its
body; its coverage is the share of those with a non-zero count, over the union
of the reports. Give one report per platform run (Linux and Windows), so a
`#[cfg(windows)]` function is graded by the run that compiles it.

Tracing macro arguments: a simple field expression on its own line inside
`trace!`/`debug!`/`info!`/`warn!`/`error!`/`event!`/`span!` is compiled twice,
once for the subscriber and once into tracing's log-fallback branch, and the
instrument attributes such lines to a region that reads zero even when the
event was emitted. Those argument lines are excluded, but only when the
macro's head line has a non-zero count (the call was reached); every excluded
line is printed with its head count so the exclusion can be audited.

Exit status: 0 when every Critical row clears the floor, 1 otherwise. A row
whose function is gone, or that no given report measured, fails.
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


TRACING_MACRO = re.compile(
    r"(?<![\w:])(?:tracing::)?(trace|debug|info|warn|error|event|span)!\s*\("
)


# One field per line and nothing that branches: `name = expr,`, `%expr,`,
# `"message",` or a closing `);`. A line with a brace, a control keyword or a
# statement can hold logic of its own, and stays graded.
SIMPLE_ARGUMENT = re.compile(r"^[^{};]*(?:\);)?$")
CONTROL_FLOW = re.compile(r"\b(?:if|else|match|loop|for|while|return)\b|=>|\?\s*$")


def is_simple_argument(code):
    code = code.strip()
    return bool(SIMPLE_ARGUMENT.match(code)) and not CONTROL_FLOW.search(code)


def macro_argument_lines(lines, lo, hi):
    """(head, argument lines) for each tracing macro call inside lo..hi."""
    calls = []
    for head in range(lo, hi + 1):
        code = strip_literals(lines[head - 1])
        match = TRACING_MACRO.search(code)
        if not match:
            continue
        depth = 0
        for n in range(head, hi + 1):
            text = strip_literals(lines[n - 1])
            if n == head:
                text = text[match.end() - 1 :]
            depth += text.count("(") - text.count(")")
            if depth <= 0:
                simple, nesting, fresh = [], 0, True
                for m in range(head + 1, n + 1):
                    code = strip_literals(lines[m - 1])
                    text = code.strip()
                    # Only a whole field on its own line, at the argument
                    # list's own level: it starts a fresh argument and ends
                    # with its comma. A continuation (`&& check(),`), a line
                    # left open (`flag = a`) or anything inside a nested
                    # block, call or array is logic, not a field.
                    if nesting == 0 and fresh and text.endswith(",") and is_simple_argument(code):
                        simple.append(m)
                    nesting += sum(code.count(c) for c in "({[") - sum(code.count(c) for c in ")}]")
                    nesting = max(nesting, 0)
                    fresh = nesting == 0 and text.endswith(",")
                calls.append((head, simple))
                break
    return calls


def fn_line(lines, name, occurrence):
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    hits = [i + 1 for i, line in enumerate(lines) if pattern.search(line)]
    return hits[occurrence - 1] if len(hits) >= occurrence else None


def repo_relative(source, root):
    """The `src/...` path of an lcov `SF:` entry, as it exists under `root`.

    Reports from different platforms carry different absolute prefixes, and a
    checkout may itself sit under a directory named `src`, so the first `/src/`
    is not the repository boundary: take the first `src/...` suffix that names
    a file in this checkout.
    """
    source = source.replace("\\", "/")
    parts = source.split("/")
    for i, part in enumerate(parts):
        if part == "src":
            candidate = "/".join(parts[i:])
            if (Path(root) / candidate).is_file():
                return candidate
    return None


def read_lcov(paths, root):
    hits, current = {}, None
    for raw in (line for path in paths for line in Path(path).read_text().splitlines()):
        if raw.startswith("SF:"):
            current = repo_relative(raw[3:], root)
            if current:
                hits.setdefault(current, {})
        elif raw.startswith("DA:") and current:
            number, count = raw[3:].split(",")[:2]
            line = int(number)
            hits[current][line] = hits[current].get(line, 0) + int(count)
    return hits


def read_inventory(path):
    rows = [line for line in Path(path).read_text().splitlines() if not line.startswith("#")]
    return list(csv.DictReader(rows, delimiter="\t"))


def grade(root, inventory, lcovs):
    hits = read_lcov(lcovs, root)
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
        excluded = []
        for head, arguments in macro_argument_lines(lines, lo, hi):
            if counts.get(head, 0) > 0:
                for n in arguments:
                    if n in counts and counts[n] == 0:
                        del counts[n]
                        excluded.append(f"{row['path']}:{n} (head {head}={hits[row['path']][head]})")
        covered = sum(1 for c in counts.values() if c > 0)
        missed = sorted(n for n, c in counts.items() if c == 0)
        pct = 100.0 * covered / len(counts)
        status = "ok" if pct >= FLOOR else "BELOW"
        results.append((status, row, lo, hi, missed, covered, len(counts), pct, excluded))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--inventory", default="docs/release/v4.0.0-critical-functions.tsv")
    parser.add_argument("--lcov", action="append", required=True, help="repeat per platform run")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)

    failed = 0
    for result in grade(args.root, args.inventory, args.lcov):
        status, row = result[0], result[1]
        where = f"{row['path']}:{row['fn']}#{row['occurrence']}"
        if status in ("ok", "BELOW"):
            _, _, lo, hi, missed, covered, total, pct, excluded = result
            print(f"{status}\t{pct:6.2f}%\t{covered}/{total}\t{where}\tlines {lo}-{hi}\tmissed={missed}")
            for line in excluded:
                print(f"  excluded tracing argument line {line}")
            failed += status == "BELOW"
        else:
            print(f"{status}\t-\t-\t{where}")
            failed += 1
    print(f"critical rows failing: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
