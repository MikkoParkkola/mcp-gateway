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
PLAN = ROOT / "docs/requirements/RELEASE-4.0.0-plan.md"
ROLLUP = ROOT / "docs/requirements/RELEASE-4.0.0-blocking-rollup.md"
# Anchored at BOTH ends. Unanchored, a typo carries: `MRTR.1abc` matches as
# far as `MRTR.1a` and is counted as that criterion, so a mistyped row is
# silently attributed to a real one rather than reported.
ID = re.compile(r"^((?:MIK-\d+|NFR)\.[A-Z0-9]+\.\d+)([a-z]?)$")

# The claim, separate from the parse. Anything opening like a criterion id
# is one for the purpose of being counted or reported.
ID_PREFIX = re.compile(r"^(?:MIK-\d+|NFR)\.")
# The verification-method vocabulary: test, measurement, inspection, demonstration.
METHOD = re.compile(r"^[TMID](, ?[TMID])*$")
# The headline sentence this script owns. Nothing else in the file may state totals.
HEADLINE = re.compile(
    r"Coverage: (\d+) criteria, (\d+) rows, (\d+) met or non-blocking, (\d+) blocking\."
)


# Tokens that carry a number without claiming a count: a version, a ticket or
# criterion ID, a date.
NOT_A_COUNT = re.compile(
    r"v?\d+(?:\.\d+)+|(?:MIK-\d+|NFR)(?:\.[A-Z0-9]+\.\d+[a-z]?)?|\d{4}-\d{2}-\d{2}"
)
# What a heading's number may say next. `10 criteria`, `7 of 17`, `3 of 3`.
SAYS_WHAT_IT_COUNTS = re.compile(r"(?:\bof\s+)?\b\d{1,3}\b(?:\s+(?:criteri\w*|of\b))?")


def heading_counts(text):
    """Headings whose number does not immediately say what it counts.

    The headline check reads ONE designated line in ONE file, so a total
    restated in a title or a section heading drifts unwatched -- both did,
    while the derived line two paragraphs below stayed right.

    Prose cannot be policed this way: `23 blocking` and `5 of the 10 criteria
    blocking` are both legitimate, and telling a stale total from a live
    subtotal needs the meaning of the sentence. A heading is narrower. It
    states a count in two shapes only, `<n> criteria` and `<n> of <m>`, so a
    number followed by anything else is a claim no check maintains.

    RESIDUAL, stated: a stale total in a PARAGRAPH is still undetectable here.
    This closes the surface that went stale, not the possibility.
    """
    bad = []
    for line in text.splitlines():
        if not re.match(r"^#{1,6} ", line):
            continue
        stripped = NOT_A_COUNT.sub("", line)
        for found in re.finditer(r"\b\d{1,3}\b", stripped):
            span = SAYS_WHAT_IT_COUNTS.match(stripped, found.start())
            preceded = stripped[: found.start()].rstrip().endswith(" of") or stripped[
                : found.start()
            ].rstrip().endswith("of")
            if not preceded and (
                span is None or span.group(0).strip() == found.group(0)
            ):
                bad.append(line)
                break
    return bad


SECTION_COUNT = re.compile(r"^#{1,6} .*?,\s*(\d+) of (\d+)\s*$")


def section_counts(text):
    """Section headings of the `<n> of <m>` shape, checked against their rows.

    `heading_counts` admits this shape because it says what it counts. Saying
    what it counts is not the same as being right about it, and nothing read
    the numbers: one heading claimed `7 of 7` over eleven rows, hiding four
    blocking criteria from anyone who trusted the title. That is the very
    defect `heading_counts` exists to catch, surviving inside its exemption.

    `<m>` is the section's criterion rows; `<n>` is those whose blocking cell
    reads `no`. The ledger's own rule makes those the met-or-N/A ones, so the
    heading and the table cannot disagree without one of them being wrong.
    """
    bad, heading, seen, clear = [], None, 0, 0

    def close():
        if heading and (clear, seen) != heading[1]:
            bad.append(
                f"{heading[0]} says {heading[1][0]} of {heading[1][1]}, its rows are {clear} of {seen}"
            )

    for line in text.splitlines():
        if re.match(r"^#{1,6} ", line):
            close()
            found = SECTION_COUNT.match(line)
            heading = (
                (
                    line.split(" — ")[0].strip("# "),
                    (int(found.group(1)), int(found.group(2))),
                )
                if found
                else None
            )
            seen = clear = 0
            continue
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not ID.match(cells[0]) or cells[-1] not in ("yes", "no"):
            continue
        seen += 1
        clear += cells[-1] == "no"
    close()
    return bad


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
        if len(cells) < 4:
            continue
        # What a criterion id OPENS with decides that the row is one, before
        # asking whether it parses. Deciding on the full anchored match instead
        # lets a typo fail the match and drop the row out of the accounting
        # entirely -- the same silence the anchor was added to end, moved one
        # step along. A row that claims to be a criterion and is not readable as
        # one is malformed, never absent.
        if not ID.match(cells[0]):
            if ID_PREFIX.match(cells[0]):
                malformed.append(cells[0])
            continue
        if cells[-1] not in ("yes", "no"):
            malformed.append(cells[0])
            continue
        found = ID.match(cells[0])
        out.append((found.group(1), cells[-1], found.group(0)))
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
            bad.append(
                f"{cells[0]} (requirement says {want!r}, row says {cells[2] if len(cells) > 2 else '<no column>'!r})"
            )
    return bad


# A cluster row in the rollup: a single-letter id or an em dash, then the
# cluster name, the parent-criterion key, and the count of ledger rows.
CLUSTER = re.compile(r"^\|\s*(?:[A-Z]|—)\s*\|[^|]*\|[^|]*\|\s*(\d+)\s*\|", re.MULTILINE)

# What a cluster row LOOKS like, before asking whether it parses. A skip on
# non-match is invisible: an invalid cluster letter or a non-numeric count
# drops the row and its criteria out of the accounting entirely, and the
# totals still balance because nothing knows the row was there. Four cells
# and a short first cell separate these from criterion rows (whose ids run
# far longer) and from the three-column group summaries.
# The first cell is restricted to word characters and the em dash so that a
# markdown header (`#`) and a separator (`---`) are not read as broken
# cluster rows -- table furniture is not a defect.
CLUSTER_SHAPE = re.compile(
    r"^\|\s*([A-Za-z0-9\u2014]{1,3})\s*\|[^|]*\|[^|]*\|([^|]*)\|"
)


# A criterion key as a rollup cluster names it: optionally MIK-prefixed, and
# possibly a range (`MRTR.1-8`) standing for the rows between its endpoints.
NAMED = re.compile(r"`((?:MIK-\d+\.|NFR\.)?[A-Z][A-Z0-9]*\.\d+[a-z]?)(?:-(\d+))?`")


def rollup_membership(criteria, text):
    """Derive each cluster's rows from the ledger and check the rollup against them.

    Every blocking row belongs to exactly one cluster, and a cluster's declared
    count is whatever its named criteria resolve to. Checking the SUM alone
    passes two cancelling errors -- the observed failure padded one cluster with
    a waived row while a blocking row sat in no cluster at all -- and checking
    only the names a cluster lists cannot see a row nobody listed. Deriving the
    membership answers both, and a range is expanded rather than sampled at its
    endpoints, because a middle row going non-blocking is how a range goes stale.
    """
    blocking = [(parent, full) for parent, flag, full in criteria if flag == "yes"]
    problems = []
    claimed = {}
    saw_cluster = False
    for line in text.splitlines():
        match = CLUSTER.match(line)
        if not match:
            shape = CLUSTER_SHAPE.match(line)
            if shape:
                problems.append(
                    f"cluster row {shape.group(1).strip()!r} does not parse: "
                    f"id must be a single capital or an em dash and the count cell "
                    f"a bare number, not {shape.group(2).strip()!r}"
                )
            continue
        saw_cluster = True
        # The criteria column only. A cluster's notes legitimately name rows that
        # LEFT it -- a waiver, a re-homing -- and reading the whole row reports
        # each of those as a stray, which teaches the reader to ignore the check.
        cluster, declared = line.split("|")[1].strip(), int(match.group(1))
        members = []
        names, unreadable = named_criteria(line.split("|")[3])
        # A cell holding no backticked span at all yields neither a name nor an
        # unreadable token, so a declared zero would match an empty membership
        # and the row would pass while naming nothing.
        if not names and not unreadable:
            problems.append(f"cluster {cluster} names no criteria")
        for token in unreadable:
            problems.append(
                f"cluster {cluster} names {token}, which is not a criterion name"
            )
        for name in names:
            # Granularity decides which ledger key answers: a parent name covers
            # every clause under it, a named clause only itself. Matching a
            # clause against parents would let a met clause ride in on a
            # blocking sibling.
            matched = [
                (full if name[-1].isalpha() else parent, full)
                for parent, full in blocking
                if _names(full if name[-1].isalpha() else parent, name)
            ]
            rows = [full for _key, full in matched]
            if not rows:
                problems.append(
                    f"cluster {cluster} names {name}, which no ledger row calls blocking"
                )
            # An unqualified name binds by suffix, so `CACHE.4` would claim rows
            # from every ticket that has a `CACHE.4` -- silently, and the counts
            # would still add up. No live name is ambiguous today; the check is
            # what keeps a second ticket reusing a component name from rewriting
            # a cluster's membership without saying so.
            # The owner is what precedes the matched name, so a fully
            # qualified name owns itself and cannot be ambiguous. Splitting the
            # full row id instead would make each clause of a parent its own
            # owner, and the one unambiguous spelling would be the one rejected.
            owners = {key[: -len(name) - 1] for key, _full in matched}
            if len(owners) > 1:
                problems.append(
                    f"cluster {cluster} names {name}, which matches rows under "
                    f"{len(owners)} tickets"
                )
            members += rows
        if len(members) != declared:
            problems.append(
                f"cluster {cluster} declares {declared} rows, "
                f"its criteria resolve to {len(members)}"
            )
        for full in members:
            claimed[full] = claimed.get(full, 0) + 1
    if not saw_cluster:
        return ["no cluster table found in the rollup"]
    for _parent, full in blocking:
        if not claimed.get(full):
            problems.append(f"{full} is blocking and sits in no cluster")
        elif claimed[full] > 1:
            problems.append(f"{full} is claimed by {claimed[full]} clusters")
    return problems


def _names(key, name):
    return key == name or key.endswith("." + name)


# Every backtick-quoted token in a criteria cell. A token the criterion-name
# pattern cannot read is REPORTED rather than skipped: a silently dropped token
# leaves a cluster naming nothing, and the declared count then has to carry the
# whole complaint -- which it cannot, because zero named rows against a declared
# count of zero reads as a clean cluster.
TOKEN = re.compile(r"`[^`]*`?")


def named_criteria(cell):
    """The criteria a cluster's rows column names, with every range expanded.

    Returns the names and the tokens this parser could not read.
    """
    unreadable = [
        tok.strip() for tok in TOKEN.findall(cell) if not NAMED.fullmatch(tok)
    ]
    names = []
    for match in NAMED.finditer(cell):
        head, end = match.group(1), match.group(2)
        if not end:
            names.append(head)
            continue
        # A range is `<name ending in a digit>-<digit>`. A head ending in a clause
        # letter (`MRTR.1a-3`) or a descending range (`MRTR.8-3`) is not one, and
        # neither expanding it nor keeping its head is honest: an author who wrote
        # a range meant more than one row, so silently counting the head lets a
        # declared count of one agree with a token that names nothing.
        start = re.search(r"\d+$", head)
        if not start or int(end) < int(start.group()):
            unreadable.append(match.group(0))
            continue
        names += [
            re.sub(r"\d+$", str(n), head)
            for n in range(int(start.group()), int(end) + 1)
        ]
    return names, unreadable


def main():
    text = STATUS.read_text()
    headings = heading_counts(text) + heading_counts(PLAN.read_text())
    if headings:
        print(
            "heading states a count that says nothing about what it counts:\n  "
            + "\n  ".join(headings),
            file=sys.stderr,
        )
        return 1
    criteria, malformed = rows(text)
    if malformed:
        print(f"malformed blocking column on: {', '.join(malformed)}", file=sys.stderr)
        return 1

    blocking = sum(1 for _, b, _s in criteria if b == "yes")
    # Matched against `declared` WITH the suffix. Folding `MRTR.10a` onto
    # `MRTR.10` here would report a requirement as covered by a row that
    # gives a verdict on a different clause of it -- the substitution this
    # whole exercise exists to stop.
    ids = {s for _i, _b, s in criteria}
    requirements = REQUIREMENTS.read_text()
    # The suffix is part of the identifier here, unlike in `ID`, which folds
    # `MRTR.9a` onto `MRTR.9` so a ledger sub-row counts against its parent.
    # A requirement declaring `.1a` and `.1b` declares TWO criteria; reading
    # them as one made every split invisible to this count.
    declared = set(
        re.findall(r"\|\s*((?:MIK-\d+|NFR)\.[A-Z0-9]+\.\d+[a-z]?)\s*\|", requirements)
    )
    methods, unreadable = required_methods(requirements)
    if unreadable:
        print(
            f"unreadable verification method on: {', '.join(unreadable)}",
            file=sys.stderr,
        )
        return 1
    mismatched = method_mismatches(text, methods)
    stale_sections = section_counts(text)
    rollup_text = ROLLUP.read_text()
    membership = rollup_membership(criteria, rollup_text)
    uncovered = sorted(declared - ids)

    totals = (len(declared), len(criteria), len(criteria) - blocking, blocking)
    print(
        f"Coverage: {totals[0]} criteria, {totals[1]} rows, "
        f"{totals[2]} met or non-blocking, {totals[3]} blocking."
    )
    if uncovered:
        print(f"requirement IDs with no row: {', '.join(uncovered)}", file=sys.stderr)
    if mismatched:
        print(
            f"NFR rows whose method disagrees with the requirement: {'; '.join(mismatched)}",
            file=sys.stderr,
        )
    if stale_sections:
        print(
            f"section headings disagreeing with their own rows: {'; '.join(stale_sections)}",
            file=sys.stderr,
        )
    for complaint in membership:
        print(complaint, file=sys.stderr)

    if "--check" not in sys.argv:
        return 0
    found = HEADLINE.search(text)
    if not found:
        print(
            "no machine-checkable coverage line in the status document", file=sys.stderr
        )
        return 1
    if tuple(int(g) for g in found.groups()) != totals:
        print(
            f"headline says {found.group(0)!r}, the tables say the line above",
            file=sys.stderr,
        )
        return 1
    return 1 if uncovered or mismatched or stale_sections or membership else 0


if __name__ == "__main__":
    sys.exit(main())
