#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
"""Count the release acceptance-criteria ledger and check the headline against it.

The headline of the status document has drifted from its own tables three times,
because it was decremented by hand while rows were added below. This derives it.

Usage:
    count-release-criteria.py            print the totals
    count-release-criteria.py --check    exit 1 if the headline disagrees
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
STATUS = ROOT / "docs/requirements/RELEASE-4.0.0-criteria-status.md"
REQUIREMENTS = ROOT / "docs/requirements/RELEASE-4.0.0-requirements.md"
ID = re.compile(r"^((?:MIK-\d+|NFR)\.[A-Z0-9]+\.\d+)([a-z]?)")
# The headline sentence this script owns. Nothing else in the file may state totals.
HEADLINE = re.compile(
    r"Coverage: (\d+) criteria, (\d+) rows, (\d+) met or non-blocking, (\d+) blocking\."
)


def rows(text):
    """Every criterion row: a table line whose last cell is exactly yes or no.

    The blocking column is the vocabulary. A cell reading anything else (`no
    (flagged)` did, twice) drops the row from the count silently, so the parser
    treats it as a malformed row and says so rather than skipping it.
    """
    out, malformed = [], []
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        # Four cells is what makes a criterion row. The group-summary tables near
        # the end carry three and would otherwise read as malformed criteria.
        if len(cells) < 4 or not ID.match(cells[0]):
            continue
        if cells[-1] not in ("yes", "no"):
            malformed.append(cells[0])
            continue
        out.append((ID.match(cells[0]).group(1), cells[-1]))
    return out, malformed


def main():
    text = STATUS.read_text()
    criteria, malformed = rows(text)
    if malformed:
        print(f"malformed blocking column on: {', '.join(malformed)}", file=sys.stderr)
        return 1

    blocking = sum(1 for _, b in criteria if b == "yes")
    ids = {i for i, _ in criteria}
    declared = set(re.findall(r"\|\s*((?:MIK-\d+|NFR)\.[A-Z0-9]+\.\d+)\s*\|", REQUIREMENTS.read_text()))
    uncovered = sorted(declared - ids)

    totals = (len(declared), len(criteria), len(criteria) - blocking, blocking)
    print(
        f"Coverage: {totals[0]} criteria, {totals[1]} rows, "
        f"{totals[2]} met or non-blocking, {totals[3]} blocking."
    )
    if uncovered:
        print(f"requirement IDs with no row: {', '.join(uncovered)}", file=sys.stderr)

    if "--check" not in sys.argv:
        return 0
    found = HEADLINE.search(text)
    if not found:
        print("no machine-checkable coverage line in the status document", file=sys.stderr)
        return 1
    if tuple(int(g) for g in found.groups()) != totals:
        print(f"headline says {found.group(0)!r}, the tables say the line above", file=sys.stderr)
        return 1
    return 1 if uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
