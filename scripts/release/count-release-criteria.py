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
# The verification-method vocabulary: test, measurement, inspection, demonstration.
METHOD = re.compile(r"^[TMID](, ?[TMID])*$")
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


def required_methods(text):
    """The verification method each NFR requirement states, keyed by ID.

    The requirements file owns these letters (T test, M measurement, I
    inspection, D demonstration). The status ledger repeats them so a reader can
    see at a glance whether a row's evidence is even the right KIND of evidence
    -- inspection cited against a requirement that says T is the failure this
    catches. A repeated value drifts unless something compares the two copies,
    which is what `method_mismatches` is for. Functional (MIK-*) requirements
    state no method, so nothing is checked for them.
    """
    methods, unreadable = {}, []
    for line in text.splitlines():
        if not line.startswith("| NFR."):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and ID.match(cells[0]):
            # The method is read POSITIONALLY, from the last cell. Add a column
            # to that table and this keys on the wrong one -- silently, because
            # any string compares fine against the status ledger's copy of the
            # same wrong string. The vocabulary is the guard: a last cell that
            # is not a method refuses rather than becoming one.
            if not METHOD.match(cells[-1]):
                unreadable.append(f"{cells[0]} ({cells[-1]!r})")
                continue
            methods[cells[0]] = cells[-1]
    return methods, unreadable


def method_mismatches(text, methods):
    """NFR rows whose stated method is absent or disagrees with the requirement."""
    bad = []
    for line in text.splitlines():
        if not line.startswith("| NFR."):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not ID.match(cells[0]):
            continue
        want = methods.get(cells[0])
        if want is None:
            continue
        if len(cells) < 6 or cells[2] != want:
            bad.append(f"{cells[0]} (requirement says {want!r}, row says {cells[2] if len(cells) > 2 else '<no column>'!r})")
    return bad


def main():
    text = STATUS.read_text()
    criteria, malformed = rows(text)
    if malformed:
        print(f"malformed blocking column on: {', '.join(malformed)}", file=sys.stderr)
        return 1

    blocking = sum(1 for _, b in criteria if b == "yes")
    ids = {i for i, _ in criteria}
    requirements = REQUIREMENTS.read_text()
    declared = set(re.findall(r"\|\s*((?:MIK-\d+|NFR)\.[A-Z0-9]+\.\d+)\s*\|", requirements))
    methods, unreadable = required_methods(requirements)
    if unreadable:
        print(f"unreadable verification method on: {', '.join(unreadable)}", file=sys.stderr)
        return 1
    mismatched = method_mismatches(text, methods)
    uncovered = sorted(declared - ids)

    totals = (len(declared), len(criteria), len(criteria) - blocking, blocking)
    print(
        f"Coverage: {totals[0]} criteria, {totals[1]} rows, "
        f"{totals[2]} met or non-blocking, {totals[3]} blocking."
    )
    if uncovered:
        print(f"requirement IDs with no row: {', '.join(uncovered)}", file=sys.stderr)
    if mismatched:
        print(f"NFR rows whose method disagrees with the requirement: {'; '.join(mismatched)}", file=sys.stderr)

    if "--check" not in sys.argv:
        return 0
    found = HEADLINE.search(text)
    if not found:
        print("no machine-checkable coverage line in the status document", file=sys.stderr)
        return 1
    if tuple(int(g) for g in found.groups()) != totals:
        print(f"headline says {found.group(0)!r}, the tables say the line above", file=sys.stderr)
        return 1
    return 1 if uncovered or mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
