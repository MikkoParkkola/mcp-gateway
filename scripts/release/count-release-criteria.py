#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
# Three identifier families: Linear tickets, non-functional requirements, and
# GitHub issues. `GH<n>` is admitted because a criterion set can be published
# on an issue before it has a Linear ticket, and the identifier the reporter
# reads is the one closure evidence has to cite.
# Anchored at BOTH ends. Unanchored, a typo carries: `MRTR.1abc` matches as
# far as `MRTR.1a` and is counted as that criterion, so a mistyped row is
# silently attributed to a real one rather than reported.
# The ledger also splits one criterion into named clauses, suffixing the id
# with ` (clause: <word>)`. That suffix is part of the row's identity and
# stays in group(0), so two clauses of one criterion remain distinct rows.
ID = re.compile(
    r"^((?:MIK-\d+|NFR|GH\d+)\.[A-Z0-9]+\.\d+)([a-z]?)(?: \(clause: [a-z]+\))?$"
)

# The claim, separate from the parse. Anything opening like a criterion id
# is one for the purpose of being counted or reported.
ID_PREFIX = re.compile(r"^(?:MIK-\d+|NFR|GH\d+)\.")

# The clause qualifier a ledger row may carry, stripped when matching a row
# against the requirement it belongs to.
CLAUSE = re.compile(r" \(clause: [a-z]+\)$")
# The verification-method vocabulary: test, measurement, inspection, demonstration.
METHOD = re.compile(r"^[TMID](, ?[TMID])*$")

# The status vocabulary the ledger's own header defines. A status outside it is
# not a harmless synonym: the header's rule is "BLOCKING unless MET or N/A", and
# the blocking column is set by hand, so an undefined word is a row whose flag
# no rule connects to its verdict. Two rows read `PASS` for three days and were
# counted non-blocking by a check that only ever policed the other column.
STATUS_WORDS = re.compile(r"^(MET|PARTIAL|ABSENT|UNWIRED|UNTESTED|N/A)(\s*\(.+\))?$")
# The headline sentence this script owns. Nothing else in the file may state totals.
HEADLINE = re.compile(
    r"Coverage: (\d+) criteria, (\d+) rows, (\d+) met or non-blocking, (\d+) blocking\."
)


# Tokens that carry a number without claiming a count: a version, a ticket or
# criterion ID, a date.
NOT_A_COUNT = re.compile(
    r"v?\d+(?:\.\d+)+|(?:MIK-\d+|NFR|GH\d+)(?:\.[A-Z0-9]+\.\d+[a-z]?)?|\d{4}-\d{2}-\d{2}"
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


def open_rows(text):
    """Criterion ids whose status is neither MET-in-any-qualified-form nor N/A.

    This is the `core open` term the burndown tracker's OPEN formula names, and
    it is NOT the blocking count the Coverage line reports. The two differ by
    every row that is PARTIAL and non-blocking, and the tracker published the
    blocking count as `core open` for six consecutive entries because nothing
    emitted the number the formula actually asks for. Emitting it is the fix:
    a term derived by hand is a term that drifts.

    Status is located exactly as `status_violations` locates it -- from the
    left, with the method regex deciding which of the two positions holds it --
    so the two can never disagree about which cell they are reading.

    The population is whatever `rows` admitted, never a second filter written
    to the same recipe. A private copy of that recipe would drop a row `rows`
    reports as malformed, and this term would then be published beside the
    blocking count while resting on a smaller set of rows -- the drift the
    function exists to end, moved one column across. The four-cell shape is
    still asked because one criterion id also heads a row in a three-column
    corrections table, and that row is not a criterion row.
    """
    admitted = {full_id for _, _, full_id in rows(text)[0]}
    out = []
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] not in admitted:
            continue
        status = cells[3] if METHOD.match(cells[2]) else cells[2]
        if not status.startswith("MET") and not status.startswith("N/A"):
            # `cells[0]` IS the admitted id: `ID` is anchored at both ends, so
            # the match that built `admitted` spans the whole cell.
            out.append(cells[0])
    return out


def status_violations(text):
    """Criterion ids whose status cell is outside the documented vocabulary.

    Counted from the LEFT, not the right: an evidence cell may contain a literal
    pipe, which moves every right-hand index and made two well-formed rows read
    as violations. NFR rows carry a verification-method column that functional
    rows do not, so the method regex decides which of the two positions holds
    the status rather than a per-prefix rule that a new prefix would silently
    escape.
    """
    out = []
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not ID.match(cells[0]) or cells[-1] not in ("yes", "no"):
            continue
        status = cells[3] if METHOD.match(cells[2]) else cells[2]
        if not STATUS_WORDS.match(status):
            out.append(f"{cells[0]} ({status[:40]})")
    return out


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


# A criterion key as a rollup cluster names it: optionally MIK-prefixed, and
# possibly a range (`MRTR.1-8`) standing for the rows between its endpoints.
NAMED = re.compile(
    r"`((?:MIK-\d+\.|NFR\.|GH\d+\.)?[A-Z][A-Z0-9]*\.\d+[a-z]?)(?:-(\d+))?`"
)


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
    headings = heading_counts(text)
    if headings:
        print(
            "heading states a count that says nothing about what it counts:\n  "
            + "\n  ".join(headings),
            file=sys.stderr,
        )
        return 1
    criteria, malformed = rows(text)
    if malformed:
        # Two branches reach here -- an unreadable id and an unreadable blocking
        # cell -- so the message names the ROW, not one of its columns. Naming
        # the blocking column sent a reader to a cell that was well formed.
        print(f"malformed criterion row: {', '.join(malformed)}", file=sys.stderr)
        return 1

    undefined = status_violations(text)
    if undefined:
        print(
            "status outside the vocabulary the ledger defines:\n  "
            + "\n  ".join(undefined),
            file=sys.stderr,
        )
        return 1

    blocking = sum(1 for _, b, _s in criteria if b == "yes")
    if "--blocking" in sys.argv:
        # The count alone sends every reader back to a hand-written regex over
        # the ledger, and a partial one found 10 of 28. The list is the same
        # parse the count already trusts, so the two cannot disagree.
        for _i, b, suffixed in criteria:
            if b == "yes":
                print(suffixed)
        return 0
    # Matched against `declared` WITH the suffix. Folding `MRTR.10a` onto
    # `MRTR.10` here would report a requirement as covered by a row that
    # gives a verdict on a different clause of it -- the substitution this
    # whole exercise exists to stop.
    ids = {s for _i, _b, s in criteria}
    # A clause row is a named PART of one declared criterion: the ledger splits
    # `MIK-7272.EXT.1` into `(clause: declare)` and `(clause: honour)` while the
    # requirement declares the unsuffixed id, which would otherwise read as
    # having no row at all. Only that qualifier is stripped -- the `.1a`/`.1b`
    # letter split stays, because those are two criteria and not two clauses.
    ids |= {CLAUSE.sub("", i) for i in ids}
    requirements = REQUIREMENTS.read_text()
    # The suffix is part of the identifier here, unlike in `ID`, which folds
    # `MRTR.9a` onto `MRTR.9` so a ledger sub-row counts against its parent.
    # A requirement declaring `.1a` and `.1b` declares TWO criteria; reading
    # them as one made every split invisible to this count.
    declared = set(
        re.findall(
            r"\|\s*((?:MIK-\d+|NFR|GH\d+)\.[A-Z0-9]+\.\d+[a-z]?)\s*\|", requirements
        )
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
    uncovered = sorted(declared - ids)

    totals = (len(declared), len(criteria), len(criteria) - blocking, blocking)
    print(
        f"Coverage: {totals[0]} criteria, {totals[1]} rows, "
        f"{totals[2]} met or non-blocking, {totals[3]} blocking."
    )
    still_open = open_rows(text)
    print(
        f"Core open: {len(still_open)} rows neither MET nor N/A"
        + (f" ({', '.join(still_open)})." if still_open else ".")
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
    return 1 if uncovered or mismatched or stale_sections else 0


if __name__ == "__main__":
    sys.exit(main())
