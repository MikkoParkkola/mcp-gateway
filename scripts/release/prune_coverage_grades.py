#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prune coverage_grade.sh's download directory to its newest runs.

    prune_coverage_grades.py <dir> <keep> <run id>...

Every run coverage_grade.sh grades leaves its artifacts and a source copy
under <git common dir>/coverage-grade/<run id>, about 50 MB each, and the
directory is shared by every worktree of the clone (26 runs filled 1.2 GB,
MIK-8217). Keeps the <keep> most recently modified run directories plus every
<run id> named (the run being graded, the self-check baseline); removes the
rest. Only directories named by a run id (digits) are touched.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def prune(root: Path, keep: int, pinned: set[str]) -> list[str]:
    runs = sorted(
        (d for d in root.iterdir() if d.is_dir() and d.name.isdigit()),
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    removed = []
    for run in runs[keep:]:
        if run.name not in pinned:
            shutil.rmtree(run)
            removed.append(run.name)
    return removed


def main(argv: list[str]) -> int:
    if len(argv) < 2 or not argv[1].isdigit():
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    root = Path(argv[0])
    if not root.is_dir():
        return 0
    removed = prune(root, int(argv[1]), set(argv[2:]))
    if removed:
        print(f"pruned {len(removed)} older coverage grade run(s) from {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
