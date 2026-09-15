#!/usr/bin/env python3
"""Fail when release-doc prose disagrees with the ledger it summarises.

Six burndown rows (`q` through `v`) were spent on one defect class: a sentence
or table cell restating a number the machine can derive, then drifting from it.
Nothing read either document programmatically, so the drift was only ever found
by hand.

The authorities here are the arrays in `tests/mik_7272_conformance.rs` and the
scope contract, never the prose. Every comparison is derived; nothing is copied.
"""

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from check_scope_acceptance import (  # noqa: E402
    BASELINE,
    ROOT,
    SCOPE,
    STATUS,
    inspect_contract,
    unique_object,
)

CONFORMANCE = pathlib.Path("tests/mik_7272_conformance.rs")
MATRIX = pathlib.Path("docs/requirements/RELEASE-4.0.0-conformance-matrix.md")
TRACKER = pathlib.Path("docs/release/v4.0.0-burndown-tracker.md")

COVERED = re.compile(r"^### Statements with evidence — COVERED \((\d+) of (\d+)\)$", re.M)
UNCOVERED = re.compile(
    r"^### Statements without evidence — UNCOVERED \((\d+) of (\d+)\)$", re.M
)
PROSE = re.compile(r"^All (\w+) major statements and minor 1-(\d+) carry", re.M)
SUMMARY = re.compile(
    r"^\| (\d{4}-\d{2}-\d{2})([a-z]+) \| (\d+) \| (\d+) \| \*\*(\d+)\*\* \| (\d+) \|", re.M
)

WORDS = {
    w: n
    for n, w in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
    )
}


class Drift(Exception):
    """A disagreement, or a document this checker can no longer read."""


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def only_match(pattern, text, path, what):
    """Exactly one match, or the document has changed shape under the check."""
    found = list(pattern.finditer(text))
    if len(found) != 1:
        raise Drift(f"{path}: expected exactly one {what}, found {len(found)}")
    return found[0]


def entries(source, name, opener):
    """Count top-level entries of a rustfmt-formatted const slice.

    Indentation is load-bearing here, which `cargo fmt --check` in CI makes a
    guarantee rather than an assumption.
    """
    head = f"const {name}:"
    start = source.find(head)
    if start < 0:
        raise Drift(f"{CONFORMANCE}: {name} not found")
    # The first `];` terminates the slice; an entry cannot contain one. A wrong
    # early cut would undercount, which fails loudly rather than passing green.
    end = source.find("];", start)
    if end < 0:
        raise Drift(f"{CONFORMANCE}: {name} has no closing `];`")
    body = source[start:end]
    return len(re.findall(rf"^    {re.escape(opener)}", body, re.M))


def check_matrix(text, covered, total):
    failures = []

    m = only_match(COVERED, text, MATRIX, "COVERED heading")
    if (int(m.group(1)), int(m.group(2))) != (covered, total):
        failures.append(
            f"{MATRIX}:{line_of(text, m.start())}: COVERED heading says "
            f"{m.group(1)} of {m.group(2)}; the arrays derive {covered} of {total}"
        )

    m = only_match(UNCOVERED, text, MATRIX, "UNCOVERED heading")
    if (int(m.group(1)), int(m.group(2))) != (total - covered, total):
        failures.append(
            f"{MATRIX}:{line_of(text, m.start())}: UNCOVERED heading says "
            f"{m.group(1)} of {m.group(2)}; the arrays derive "
            f"{total - covered} of {total}"
        )

    return failures


def check_prose(text, majors, minors):
    m = only_match(PROSE, text, MATRIX, "statement-population sentence")
    word = m.group(1).lower()
    if word not in WORDS:
        raise Drift(
            f"{MATRIX}:{line_of(text, m.start())}: "
            f"'{m.group(1)}' is not a number word this check knows"
        )
    if (WORDS[word], int(m.group(2))) != (majors, minors):
        return [
            f"{MATRIX}:{line_of(text, m.start())}: prose says {m.group(1)} major "
            f"and minor 1-{m.group(2)}; the arrays hold {majors} and {minors}"
        ]
    return []


def check_tracker(text, pending, blocking):
    rows = list(SUMMARY.finditer(text))
    if not rows:
        raise Drift(f"{TRACKER}: no summary rows matched")
    # Newest by parsed key, so an out-of-order append cannot be read as current.
    newest = max(rows, key=lambda r: (r.group(1), len(r.group(2)), r.group(2)))
    at = f"{TRACKER}:{line_of(text, newest.start())}"
    said_blocking, said_pending, said_total = (int(newest.group(i)) for i in (3, 4, 5))

    failures = []
    if said_blocking + said_pending != said_total:
        failures.append(
            f"{at}: row {newest.group(1)}{newest.group(2)} totals "
            f"{said_blocking} + {said_pending} = {said_blocking + said_pending}, "
            f"not the {said_total} it states"
        )
    if (said_blocking, said_pending) != (blocking, pending):
        failures.append(
            f"{at}: row {newest.group(1)}{newest.group(2)} states {said_blocking} "
            f"blocking / {said_pending} pending; the scope contract derives "
            f"{blocking} / {pending}"
        )
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="repository root to read; lets the negative control run on a copy "
        "instead of mutating documents other sessions are editing",
    )
    root = parser.parse_args(argv).root

    try:
        data = json.loads((root / STATUS).read_text(), object_pairs_hook=unique_object)
        errors, pending, blockers = inspect_contract(
            root, (root / SCOPE).read_text(), data, (root / BASELINE).read_text()
        )
        if errors:
            raise Drift(
                "the scope contract is itself inconsistent, so its counts cannot "
                "be an authority:\n  " + "\n  ".join(errors)
            )

        source = (root / CONFORMANCE).read_text()
        majors = entries(source, "MAJOR", "Row {")
        minors = entries(source, "MINOR", "Row {")
        gaps = entries(source, "TRACKED_GAPS", "(")
        total = majors + minors

        matrix = (root / MATRIX).read_text()
        tracker = (root / TRACKER).read_text()

        failures = (
            check_matrix(matrix, total - gaps, total)
            + check_prose(matrix, majors, minors)
            + check_tracker(tracker, len(pending), len(blockers))
        )
    except (OSError, ValueError, Drift) as error:
        print(f"Cannot check doc/ledger agreement: {error}", file=sys.stderr)
        return 2

    if failures:
        print("Release-doc prose disagrees with its ledgers:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"Doc/ledger agreement: {total} statements ({majors} major, {minors} minor), "
        f"{gaps} tracked gaps; {len(blockers)} blocking / {len(pending)} pending."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
