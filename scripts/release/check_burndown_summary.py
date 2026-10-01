#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when the burndown tracker's summary disagrees with the two ledger checks.

The tracker's top table restates the counts `count-release-criteria.py --check`
and `check_scope_acceptance.py --release` print. It drifted after every
criteria change because nothing compared them (MIK-7730). This compares them.

Usage:
    python3 scripts/release/check_burndown_summary.py
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs/internal/release/v4.0.0-burndown-tracker.md"


CORE_ROW = re.compile(
    r"^\| Core release criteria \|[^|]*\| (\d+) rows over (\d+) criteria \| (\d+)\b[^|]*\| \*\*(\d+)\*\* blocking",
    re.MULTILINE,
)
SCOPE_ROW = re.compile(
    r"^\| Scope-update criteria \|[^|]*\| (\d+) \| (\d+) \((\d+) met, (\d+) waived\) \| \*\*(\d+)\*\* \|",
    re.MULTILINE,
)
CORE_LINE = re.compile(r"Coverage: (\d+) criteria, (\d+) rows, (\d+) met or non-blocking, (\d+) blocking\.")
SCOPE_LINE = re.compile(r"Scope contract consistent: (\d+) criteria \((\d+) met / (\d+) waived / (\d+) pending\)")
KEYS = ("core_criteria", "core_rows", "core_ok", "core_blocking",
        "scope_total", "scope_met", "scope_waived", "scope_pending")


def tracker_counts(text: str) -> dict:
    """The counts the tracker's summary table states; empty keys if a row is missing."""
    counts = {}
    if core := CORE_ROW.search(text):
        rows, criteria, ok, blocking = map(int, core.groups())
        counts.update(core_criteria=criteria, core_rows=rows, core_ok=ok, core_blocking=blocking)
    if scope := SCOPE_ROW.search(text):
        total, done, met, waived, pending = map(int, scope.groups())
        if done != met + waived:
            counts["scope_inconsistent"] = f"{done} != {met} met + {waived} waived"
        counts.update(scope_total=total, scope_met=met, scope_waived=waived, scope_pending=pending)
    return counts


def core_counts(output: str) -> dict:
    """The counts in count-release-criteria.py --check output."""
    m = CORE_LINE.search(output)
    return dict(zip(KEYS[:4], map(int, m.groups()))) if m else {}


def scope_counts(output: str) -> dict:
    """The counts in check_scope_acceptance.py --release output."""
    m = SCOPE_LINE.search(output)
    return dict(zip(KEYS[4:], map(int, m.groups()))) if m else {}


def mismatches(stated: dict, measured: dict) -> list[str]:
    """One line per count the tracker states differently, or cannot state.

    Fails closed: a count missing on either side is a mismatch.
    """
    problems = []
    if "scope_inconsistent" in stated:
        problems.append(f"tracker scope row does not add up: {stated['scope_inconsistent']}")
    for key in KEYS:
        if key not in measured:
            problems.append(f"{key}: the ledger check printed no value")
        elif key not in stated:
            problems.append(f"{key}: the tracker summary states no value")
        elif stated[key] != measured[key]:
            problems.append(f"{key}: tracker says {stated[key]}, ledger check says {measured[key]}")
    return problems


def run(script: str, *args: str) -> str:
    done = subprocess.run([sys.executable, str(ROOT / "scripts/release" / script), *args],
                          capture_output=True, text=True, cwd=ROOT)
    return done.stdout + done.stderr


def main() -> int:
    stated = tracker_counts(TRACKER.read_text(encoding="utf-8"))
    measured = {**core_counts(run("count-release-criteria.py", "--check")),
                **scope_counts(run("check_scope_acceptance.py", "--release"))}
    problems = mismatches(stated, measured)
    for problem in problems:
        print(f"{TRACKER.relative_to(ROOT)}: {problem}")
    if problems:
        print("Update the tracker's summary table and provenance line from both checks.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
