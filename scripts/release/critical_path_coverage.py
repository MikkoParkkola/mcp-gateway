#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade each named critical path's unique-line coverage from one lcov report.

Reads SF and DA records, counting each file's distinct lines once and keeping
the largest count for repeated lines. A line is covered when its count is > 0.
The mapping and converted 2026-10-01 baseline floors come from
docs/release/v4.0.0-critical-path-coverage.md ("The mapping"; "The baseline").
A change there is a change here, in the same commit.

Exit status: 0 when every path clears the Standard floor and its recorded
baseline, 1 otherwise. A path with no measured file fails. 3 when the report is
absent, empty, unreadable or unparseable: nothing was graded.
"""

import argparse
import re
import sys

FLOOR = 80.0

# (name, prefixes, 2026-10-01 `--tests` baseline converted to unique-line %).
PATHS = [
    ("startup", ["src/gateway/server/"], 92.84),
    ("OAuth", ["src/oauth/"], 79.67),
    ("HTTP dispatch", ["src/transport/http/", "src/gateway/router/"], 94.69),
    (
        "stdio dispatch",
        [
            "src/transport/stdio.rs",
            # Its start sequence, split out of stdio.rs: the same lines,
            # graded where they now live.
            "src/transport/stdio_start.rs",
            # Its child environment, split out of stdio.rs earlier and
            # restored here.
            "src/transport/stdio_env.rs",
            "src/gateway/server/stdio_channel.rs",
            "src/transport/command_split.rs",
        ],
        89.66,
    ),
    ("bridge", ["src/gateway/input_bridge.rs"], 90.49),
    (
        "tasks",
        [
            "src/gateway/task_service/",
            "src/gateway/router/handlers/tasks.rs",
            # Its owner family, split out of tasks.rs: the same
            # lines, graded where they now live. Named as a file, not tasks/,
            # so the test children under tasks/ are not graded as product.
            "src/gateway/router/handlers/tasks/owner.rs",
            "src/gateway/meta_mcp/task_confirmation",
        ],
        94.87,
    ),
    (
        "account paths",
        [
            "src/personal_accounts/",
            "src/gateway/server/account_bindings.rs",
            "src/config/account_bindings.rs",
            "src/identity_propagation/",
        ],
        95.93,
    ),
]


def relative(filename):
    """The repository-relative path: llvm-cov reports absolute ones."""
    filename = filename.replace("\\", "/")
    if filename.startswith("src/"):
        return filename
    _, sep, rest = filename.partition("/src/")
    return "src/" + rest if sep else filename


def read_lcov(text):
    """Read complete file records without consulting the graded source tree."""
    records = text.splitlines()
    if text.lstrip().startswith(("{", "[")) or not any(
        line.startswith("SF:") for line in records
    ):
        raise ValueError("not an lcov report")
    files = {}
    current = None
    for line in records:
        if not line:
            continue
        if line.startswith("SF:"):
            if current is not None or not line[3:].strip():
                raise ValueError("corrupt lcov: invalid or unfinished SF record")
            current = files.setdefault(relative(line[3:]), {})
        elif line == "end_of_record":
            if current is None:
                raise ValueError("corrupt lcov: end_of_record without SF")
            current = None
        elif line.startswith("DA:"):
            if current is None or not re.fullmatch(r"DA:[+-]?[0-9]+,[+-]?[0-9]+", line):
                raise ValueError("corrupt lcov: DA requires two integers within SF")
            number, count = map(int, line[3:].split(","))
            current[number] = max(current.get(number, count), count)
        elif line.startswith("TN:") and current is None:
            continue
        elif current is not None and line.startswith(
            ("FN:", "FNDA:", "FNF:", "FNH:", "LF:", "LH:", "BRDA:", "BRF:", "BRH:")
        ):
            # Summary counters can include overlapping function lines; only DA
            # records define the path measurement, so LF/LH are not cross-checked.
            continue
        else:
            raise ValueError("corrupt lcov: unexpected record")
    if current is not None:
        raise ValueError("corrupt lcov: missing end_of_record")
    return files


def grade(report):
    """One row per path: (name, files, covered, total, percent, failures)."""
    rows = []
    for name, prefixes, baseline in PATHS:
        hits = [lines for path, lines in report.items() if path.startswith(tuple(prefixes))]
        covered = sum(sum(count > 0 for count in lines.values()) for lines in hits)
        total = sum(len(lines) for lines in hits)
        percent = 100.0 * covered / total if total else 0.0
        failures = []
        if not total:
            failures.append("no measured file")
        if percent < FLOOR:
            failures.append(f"below the {FLOOR:.0f}% floor")
        if percent < baseline:
            failures.append(f"below its {baseline:.2f}% baseline")
        rows.append((name, len(hits), covered, total, percent, failures))
    return rows


# Exit status when the report is absent. Equal to critical_function_coverage's
# INPUT_MISSING (a test pins it); defined here, not imported, because
# coverage_grade.sh may run this file from an older revision.
INPUT_MISSING = 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", metavar="REPORT", help="one Linux lcov report")
    args = parser.parse_args(argv)
    # Absent, empty or unreadable all mean the Linux job uploaded no report.
    try:
        with open(args.report, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = ""
    except UnicodeError:
        print("corrupt lcov: report is not UTF-8")
        return INPUT_MISSING
    if not text.strip():
        print(f"input missing: {args.report}")
        print("NOT GRADED: the coverage report is missing, so no path was graded")
        return INPUT_MISSING
    try:
        report = read_lcov(text)
    except ValueError as error:
        print(f"{error}: {args.report}")
        print("NOT GRADED: the coverage report is invalid, so no path was graded")
        return INPUT_MISSING
    rows = grade(report)
    for name, count, covered, total, percent, failures in rows:
        verdict = "; ".join(failures) if failures else "ok"
        print(f"{name:15} files={count:3} {covered}/{total} {percent:6.2f}%  {verdict}")
    failing = sum(bool(row[5]) for row in rows)
    print(f"paths failing: {failing}")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
