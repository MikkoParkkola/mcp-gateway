#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Changelog fragments: one file per pull request instead of a shared section.

Every open pull request used to edit `## [Unreleased]` in CHANGELOG.md, so each
merge made the others conflict. A PR now adds `changelog.d/<number>.<type>.md`
holding its bullet(s), and the release folds them in. A further PR under the
same number adds `<number>-<n>.<type>.md` (n a positive number, no leading zero).

    changelog_fragments.py check --base <ref> [--head <ref>]
        Fail a PR that changes src/ without adding a fragment. The label
        `no-changelog` (in the PR_LABELS environment variable, comma separated)
        waives it. A misnamed fragment always fails.

    changelog_fragments.py assemble [--dry-run]
        Append every fragment to its `### <Type>` subsection under
        `## [Unreleased]`, creating the subsection when missing, then delete
        the fragments. --dry-run prints the result and changes nothing.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[2]
FRAGMENT_DIR = "changelog.d"
# Keep a Changelog order; a missing subsection is created in this order.
TYPES = ("added", "changed", "removed", "fixed", "security")
# Group 1 is the number, group 2 the type; the optional -<n> suffix names a
# further fragment under one number. No 0 and no leading zero, so every
# accepted name is the only spelling of its stem and sorts after the bare one.
FRAGMENT = re.compile(r"^(\d+)(?:-[1-9]\d*)?\.(" + "|".join(TYPES) + r")\.md$")
# Files in changelog.d/ that are not fragments.
NOT_FRAGMENTS = {".gitkeep"}
SKIP_LABEL = "no-changelog"
# What ships: the gateway crate, the workspace crates, the container images and
# the platforms they are built for, the capability catalogue, and the registry
# and npm package metadata.
SOURCE = re.compile(
    r"^(src/|crates/[^/]+/src/|Dockerfile[^/]*$|\.github/workflows/docker[^/]*\.ya?ml$"
    r"|capabilities/|server\.json$|npm/)"
)
# A bare tracker id and an acceptance id (<id>.<AREA>.<n>), read from the public
# hygiene rule's own patterns, so the fold drops exactly what the checks refuse
# and keeps what they set aside. A missing pattern raises: it is never guessed.
_PATTERNS = pathlib.Path(__file__).resolve().parents[2] / "scripts/dev/public-hygiene-patterns.sh"


def _hygiene_pattern(name: str) -> str:
    for line in _PATTERNS.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip("'").replace("[:alnum:]", "A-Za-z0-9")
    raise RuntimeError(f"{_PATTERNS}: no {name}")


TRACKER_ID = re.compile(_hygiene_pattern("ticket_id_regex"))
ACCEPTANCE_ID = re.compile(_hygiene_pattern("ac_id_regex"))
# One parenthetical part that is only an id, or an id and its label (`I2`, `MIN.2`).
# The id itself is the rule's pattern after its leading boundary group `(^|[^...])`.
ID_PART = re.compile(TRACKER_ID.pattern.split(")", 1)[1] + r"(?: [A-Z][A-Z0-9.]*[0-9])?")


def _enclosing(masked: str, at: int) -> tuple[int, int] | None:
    """(open, close) of the innermost parenthetical around `at`, or None."""
    depth = 0
    for o in range(at - 1, -1, -1):
        if masked[o] == ")":
            depth += 1
        elif masked[o] == "(":
            if depth == 0:
                break
            depth -= 1
    else:
        return None
    depth = 0
    for c in range(at, len(masked)):
        if masked[c] == "(":
            depth += 1
        elif masked[c] == ")":
            if depth == 0:
                return o, c
            depth -= 1
    return None


def _parts(masked: str, o: int, c: int) -> list[tuple[int, int]]:
    """Spans of the `,`/`;`-separated parts inside (o, c), split at the top level only."""
    spans, start, depth = [], o + 1, 0
    for i in range(o + 1, c):
        ch = masked[i]
        depth += ch == "("
        depth -= ch == ")"
        if ch in ",;" and depth == 0:
            spans.append((start, i))
            start = i + 1
    return spans + [(start, c)]


def _code_blind(masked: str) -> tuple[str, list[int], list[tuple[int, int]]]:
    """(`masked` with the inside of each one-line code span replaced by `x`,
    the offsets of backtick runs that close nothing, and where each span starts and ends).

    A code span is read as CommonMark reads it: a run of N backticks opens
    it, and the next run of exactly N on the same line closes it, so no `(`,
    `)`, `,` or `;` written in code splits a parenthetical. A run with no
    closing run is left as text and reported, so the caller can refuse it."""
    runs = list(re.finditer(r"`+", masked))
    out, unclosed, spans, i = list(masked), [], [], 0
    while i < len(runs):
        opening = runs[i]
        width = len(opening.group())
        closing = next(
            (j for j in range(i + 1, len(runs))
             if len(runs[j].group()) == width and "\n" not in masked[opening.end():runs[j].start()]),
            None,
        )
        if closing is None:
            unclosed.append(opening.start())
            i += 1
            continue
        out[opening.end():runs[closing].start()] = "x" * (runs[closing].start() - opening.end())
        spans.append((opening.start(), runs[closing].end()))
        i = closing + 1
    return "".join(out), unclosed, spans


def _code_seen(t: str) -> tuple[list[str], int]:
    """Each code span of `t` as `_code_blind` pairs it, and the count of escaped
    backticks: a drop that changes either has changed what a reader sees as code."""
    return [t[a:b] for a, b in _code_blind(t)[2]], t.count("\\`")


def _kept_text(piece: str) -> str:
    """A kept part as written, trimmed; only a run of whitespace holding a line
    break becomes one space, so a rejoined parenthetical sits on one line and
    the spaces inside a code span stay as they are."""
    return re.sub(r"[ \t]*\n\s*", " ", piece.strip())


def drop_ids(text: str) -> tuple[str, list[str]]:
    """`text` without its bare tracker ids, and the ids that cannot be dropped.

    An id is dropped when it is a whole part of a parenthetical, alone or with its
    label; a parenthetical left empty goes with the space before it. An id in
    prose, or among other words in a part, would leave a broken sentence: it is
    returned as `<line>: <why>` for the fragment to be reworded, and the text is
    returned unchanged. An id beside code is refused the same way, so the fold
    never rewrites a code span.
    """

    def scan(t: str):
        masked = ACCEPTANCE_ID.sub(lambda m: "\0" * len(m.group(0)), t)
        blind, unclosed, _ = _code_blind(masked)
        spans, problems = [], []
        for m in TRACKER_ID.finditer(masked):
            at = m.end(1)  # the id, past the boundary character the pattern consumes
            line = t.count("\n", 0, at) + 1
            # Its bullet ends at a blank line or at the next bullet; no code span crosses those.
            start = max(t.rfind("\n- ", 0, at), t.rfind("\n\n", 0, at)) + 1
            end = min((e for e in (t.find("\n- ", at), t.find("\n\n", at)) if e >= 0), default=len(t))
            # Fenced or indented block code is invisible to the span reader, so refuse outright.
            if re.search(r"(?m)^[ \t]*(```|~~~)|^ {6,}\S", t[start:end]):
                problems.append(f"{line}: a tracker id in a bullet holding a code block; "
                                "move the id out of the bullet, or reword")
                continue
            span = _enclosing(blind, at)
            if span is None:
                problems.append(f"{line}: a tracker id in prose; reword the line without it")
                continue
            # The fold never rewrites a parenthetical that holds code, at any depth
            # around the id: it refuses, so no reading of the backticks can change a command.
            around = span
            while around is not None and "`" not in t[around[0]:around[1]]:
                around = _enclosing(blind, around[0])
            if around is not None:
                problems.append(f"{line}: a tracker id in a parenthetical that holds code; "
                                "move the id out of the parenthetical that holds code, or reword")
                continue
            # An escaped backtick, or a run that closes nothing on its own line,
            # anywhere in the id's bullet leaves where code starts or ends in doubt,
            # as a code span may run across line breaks.
            if "\\`" in t[start:end] or any(start <= u < end for u in unclosed):
                problems.append(f"{line}: a tracker id in a bullet with an escaped or unclosed backtick; "
                                "close the span or reword the line")
                continue
            part = next(p for p in _parts(blind, *span) if p[0] <= at < p[1])
            if not ID_PART.fullmatch(" ".join(masked[part[0]:part[1]].split())):
                problems.append(f"{line}: a tracker id among other words; reword the line without it")
                continue
            if span not in spans:
                spans.append(span)
        return masked, blind, spans, problems

    masked, blind, spans, problems = scan(text)
    if problems:
        return text, problems
    source = text
    while spans:
        # The last parenthetical first, then scan again: a rewrite moves every later offset.
        o, c = max(spans)
        before = text
        # Each kept part keeps its own text and the separator written before it
        # (`,` or `;`); the first kept part needs none.
        kept = [(text[a - 1] if a > o + 1 else "", _kept_text(text[a:b]))
                for a, b in _parts(blind, o, c)
                if text[a:b].strip() and not TRACKER_ID.search(masked[a:b])]
        if kept:
            inner = kept[0][1] + "".join(f"{sep} {piece}" for sep, piece in kept[1:])
            text = f"{text[:o]}({inner}){text[c + 1:]}"
        else:
            start, end = text.rfind("\n", 0, o) + 1, text.find("\n", c)
            end = len(text) if end < 0 else end
            if not text[start:o].strip() and not text[c + 1:end].strip():
                # Alone on its lines: they go too, as a line of spaces reads as a blank
                # line; a blank line the source has inside it stays, as written.
                blanks = "".join(f"{blank}\n" for blank in text[start:end].split("\n") if not blank.strip())
                if end == len(text) and start and not blanks:
                    start -= 1  # the text ends on those lines: their line break goes too
                text = text[:start] + blanks + text[end + 1:]
            else:
                text = text[: o - 1 if o and text[o - 1] == " " else o] + text[c + 1:]
        # The invariant behind every code rule above: a drop leaves each code span as it was.
        if _code_seen(text) != _code_seen(before):
            line = before.count("\n", 0, o) + 1
            return source, [f"{line}: dropping the tracker id would change a code span; reword the line"]
        masked, blind, spans, _ = scan(text)
    return text, []


def _stem(name: str) -> str:
    """`<number>` or `<number>-<n>`: what a retype keeps and the fold orders by."""
    return name.split(".", 1)[0]


def _order(name: str) -> tuple[int, int]:
    """Number, then suffix (none sorts first), so 9-10 follows 9-2."""
    number, _, n = _stem(name).partition("-")
    return int(number), int(n or 0)


def fragment_name_errors(names: list[str]) -> list[str]:
    return [
        f"{FRAGMENT_DIR}/{n}: fragment names are <number>.<type>.md or "
        f"<number>-<n>.<type>.md, type one of {', '.join(TYPES)}"
        for n in names
        if n not in NOT_FRAGMENTS and not FRAGMENT.match(n)
    ]


def check(
    changes: list[tuple[str, str]], labels: set[str], remaining: list[str] = ()
) -> list[str]:
    """Errors for a PR's `git diff --name-status` rows (status, path).

    `remaining` lists the fragments left in the PR's tree: a release fold
    folds them all, so it leaves none.
    """
    added = [
        path.split("/", 1)[1]
        for status, path in changes
        if path.startswith(f"{FRAGMENT_DIR}/") and status.startswith("A")
    ]
    errors = fragment_name_errors(added)
    if SKIP_LABEL in labels:
        return errors
    # A fragment re-added under the same name with another type is a retype
    # (the diff runs without rename detection, so a rename arrives as a delete
    # plus an add), not a loss. Pairs are one to one (MIK-7946): each addition
    # excuses one deletion of its name (number and any suffix), and an addition
    # so paired replaces an old entry rather than adding a new one.
    unpaired = Counter(_stem(n) for n in added if FRAGMENT.match(n))
    deleted = []
    for status, path in changes:
        name = path.split("/", 1)[1] if path.startswith(f"{FRAGMENT_DIR}/") else ""
        if not (status.startswith("D") and FRAGMENT.match(name)):
            continue
        stem = _stem(name)
        if unpaired[stem]:
            unpaired[stem] -= 1
        else:
            deleted.append(path)
    touches_shipped = any(SOURCE.match(path) for _, path in changes)
    if touches_shipped and not any(unpaired.values()):
        errors.append(
            f"this PR changes shipped files but adds no {FRAGMENT_DIR}/<number>[-<n>].<type>.md; "
            f"add one (see CONTRIBUTING.md) or apply the '{SKIP_LABEL}' label"
        )
    # Only the release fold, which deletes every fragment it folds in, edits
    # CHANGELOG.md; a hand edit brings back the conflicts fragments remove.
    folds = not any(FRAGMENT.match(n) for n in remaining) and any(
        status.startswith("D")
        and path.startswith(f"{FRAGMENT_DIR}/")
        and FRAGMENT.match(path.split("/", 1)[1])
        for status, path in changes
    )
    edits_changelog = any(path == "CHANGELOG.md" for _, path in changes)
    if edits_changelog and not folds:
        errors.append(
            f"this PR edits CHANGELOG.md; put the entry in {FRAGMENT_DIR}/<number>[-<n>].<type>.md "
            f"instead, or apply the '{SKIP_LABEL}' label"
        )
    # A fragment leaves only by being folded into CHANGELOG.md; deleting one
    # any other way, unpaired with a retype above, loses another PR's entry.
    if deleted and not (edits_changelog and folds):
        errors.append(
            f"this PR deletes {', '.join(deleted)} without folding every fragment into "
            f"CHANGELOG.md (scripts/release/changelog_fragments.py assemble)"
        )
    return errors


def assemble(changelog: str, fragments: dict[str, str]) -> str:
    """Fold `fragments` ({file name: text}) into the Unreleased section, without bare tracker ids.

    Raises ValueError naming each file and line holding an id the fold cannot drop
    (in prose, or among words in a parenthetical): it is reworded at source, never
    written. Released sections are history and keep their text.
    """
    if not fragments:
        return changelog
    lines = changelog.split("\n")
    if "## [Unreleased]" not in lines:
        # Right after a release: open a new Unreleased section above it.
        first = next((i for i, x in enumerate(lines) if x.startswith("## ")), len(lines))
        lines[first:first] = ["## [Unreleased]", ""]
    start = lines.index("## [Unreleased]")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    clean = {n: drop_ids(text) for n, text in fragments.items()}
    section, left = drop_ids("\n".join(lines[start:end]))
    problems = [f"{FRAGMENT_DIR}/{n}:{p}" for n in sorted(clean, key=_order) for p in clean[n][1]]
    problems += [f"CHANGELOG.md:{start + int(p.split(':', 1)[0])}:{p.split(':', 1)[1]}" for p in left]
    if problems:
        raise ValueError("\n".join(problems))
    section = section.split("\n")
    ordered = sorted(fragments, key=lambda n: (*_order(n), n))
    for kind in TYPES:
        body = [
            clean[n][0].strip("\n") for n in ordered if FRAGMENT.match(n)[2] == kind
        ]
        if not body:
            continue
        heading = f"### {kind.capitalize()}"
        if heading not in section:
            # Before the first subsection of a later type, else at the end.
            later = [f"### {k.capitalize()}" for k in TYPES[TYPES.index(kind) + 1 :]]
            at = next((i for i, line in enumerate(section) if line in later), None)
            if at is None:
                while section and section[-1] == "":
                    section.pop()
                section += ["", heading, ""]
                at = len(section)
            else:
                section[at:at] = [heading, ""]
                at += 2
        else:
            top = section.index(heading)
            at = next(
                (i for i in range(top + 1, len(section)) if section[i].startswith("### ")),
                len(section),
            )
            while section[at - 1] == "":
                at -= 1
        # Each fragment is kept as written: its own bullet(s), no blank line.
        block = [line for text in body for line in text.split("\n")]
        if section[at - 1] == heading:
            block.insert(0, "")
        if at < len(section) and section[at] != "":
            block.append("")
        section[at:at] = block
    while section and section[-1] == "":
        section.pop()
    section.append("")
    return "\n".join(lines[:start] + section + lines[end:])


def _changes(base: str, head: str) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "diff", "--name-status", "--no-renames", f"{base}...{head}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [tuple(row.split("\t", 1)) for row in out.splitlines() if row]


def _fragment_names() -> list[str]:
    frag_dir = ROOT / FRAGMENT_DIR
    return sorted(p.name for p in frag_dir.iterdir()) if frag_dir.is_dir() else []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--base", required=True)
    c.add_argument("--head", default="HEAD")
    a = sub.add_parser("assemble")
    a.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.cmd == "check":
        labels = {x.strip() for x in os.environ.get("PR_LABELS", "").split(",") if x.strip()}
        errors = check(_changes(args.base, args.head), labels, _fragment_names())
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1 if errors else 0

    frag_dir = ROOT / FRAGMENT_DIR
    names = _fragment_names()
    errors = fragment_name_errors(names)
    errors += [f"{FRAGMENT_DIR}/{n}: not a regular file" for n in names if not (frag_dir / n).is_file()]
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    errors += [
        f"{FRAGMENT_DIR}/{n}: empty fragment"
        for n in names
        if FRAGMENT.match(n) and not (frag_dir / n).read_text(encoding="utf-8").strip()
    ]
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    fragments = {
        n: (frag_dir / n).read_text(encoding="utf-8") for n in names if FRAGMENT.match(n)
    }
    changelog_path = ROOT / "CHANGELOG.md"
    try:
        result = assemble(changelog_path.read_text(encoding="utf-8"), fragments)
    except ValueError as refused:
        # An id the fold cannot drop: nothing is written or deleted.
        for e in str(refused).splitlines():
            print(f"error: {e}", file=sys.stderr)
        return 1
    if args.dry_run:
        sys.stdout.write(result)
        return 0
    changelog_path.write_text(result, encoding="utf-8")
    for n in fragments:
        (frag_dir / n).unlink()
    print(f"folded {len(fragments)} fragment(s) into CHANGELOG.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
