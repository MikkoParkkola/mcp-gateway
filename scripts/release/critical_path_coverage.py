#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade each named critical path's line coverage (NFR.BUILD.1 C5, MIK-7324.COV.3).

Reads `cargo llvm-cov report --summary-only --json` output and sums covered and
total lines over the files under each path's prefixes. The mapping, the floor
and the baselines are the ones in docs/release/v4.0.0-critical-path-coverage.md
("The mapping"; the `--tests` table under "Measurement, all seven paths,
2026-10-01"); a change there is a change here, in the same commit.

Exit status: 0 when every path clears the Standard floor and its recorded
baseline, 1 otherwise. A path with no measured file fails. 3 when the report is
absent, empty, unreadable or unparseable: nothing was graded (MIK-8265).
"""

import argparse
import json
import sys

FLOOR = 80.0

# (name, prefixes, 2026-10-01 `--tests` baseline %).
PATHS = [
    ("startup", ["src/gateway/server/"], 92.45),
    ("OAuth", ["src/oauth/"], 79.23),
    ("HTTP dispatch", ["src/transport/http/", "src/gateway/router/"], 94.40),
    (
        "stdio dispatch",
        [
            "src/transport/stdio.rs",
            "src/gateway/server/stdio_channel.rs",
            "src/transport/command_split.rs",
        ],
        88.76,
    ),
    ("bridge", ["src/gateway/input_bridge.rs"], 90.61),
    (
        "tasks",
        [
            "src/gateway/task_service/",
            "src/gateway/router/handlers/tasks.rs",
            "src/gateway/meta_mcp/task_confirmation",
        ],
        94.73,
    ),
    (
        "account paths",
        [
            "src/personal_accounts/",
            "src/gateway/server/account_bindings.rs",
            "src/config/account_bindings.rs",
            "src/identity_propagation/",
        ],
        95.52,
    ),
]


def relative(filename):
    """The repository-relative path: llvm-cov reports absolute ones."""
    filename = filename.replace("\\", "/")
    if filename.startswith("src/"):
        return filename
    _, sep, rest = filename.partition("/src/")
    return "src/" + rest if sep else filename


def grade(report):
    """One row per path: (name, files, covered, total, percent, failures)."""
    files = [
        (relative(f["filename"]), f["summary"]["lines"])
        for data in report["data"]
        for f in data["files"]
    ]
    rows = []
    for name, prefixes, baseline in PATHS:
        hits = [lines for path, lines in files if path.startswith(tuple(prefixes))]
        covered = sum(lines["covered"] for lines in hits)
        total = sum(lines["count"] for lines in hits)
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
# coverage_grade.sh may run this file from an older revision (MIK-8265).
INPUT_MISSING = 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", help="cargo llvm-cov --summary-only --json output")
    args = parser.parse_args(argv)
    # Absent, empty or unreadable all mean the Linux job uploaded no report.
    try:
        with open(args.report, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = ""
    try:
        report = json.loads(text) if text.strip() else None
    except ValueError:  # truncated or corrupt: as unusable as an absent report
        report = None
    if not (isinstance(report, dict) and isinstance(report.get("data"), list)):
        report = None  # JSON, but not an llvm-cov summary report
    if report is None:
        print(f"input missing: {args.report}")
        print("NOT GRADED: the coverage report is missing, so no path was graded")
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
