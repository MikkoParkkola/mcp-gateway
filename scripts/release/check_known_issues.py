# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Known issues gate for the release notes.

--check (every PR): the "## Known issues" section must not name a later
release. Nothing in 4.0 is deferred to 4.0.1, so a "fixed in 4.0.1" line is
a promise the release plan no longer makes.

--release (at a tag): the section must also be empty or absent. A known issue
left at a final tag is shipped, so it blocks the tag instead. A prerelease tag
(v4.0.0-beta.N, v4.0.0-rc.N) may ship open items as known gaps
(docs/release/v4.0.0-prerelease-channel.md), so only the later-release rule
applies to it. The tag is --tag, else $GITHUB_REF_NAME; anything that is not a
v4.0.0-beta.N or v4.0.0-rc.N tag, a branch name included, is held to the
final-tag rule.

The section is read line by line and fails closed: a doubtful heading counts
as a start and never as an end, so an odd Markdown shape can only make the
gate read more of the notes. End a section with a plain "## Heading" at
column 0.

Exit 0 when the gate holds, 1 otherwise (an unreadable notes file included).
"""

import argparse
import os
import pathlib
import re
import sys

DEFAULT_NOTES = "docs/release/v4.0.0-release-notes-DRAFT.md"
LATER_RELEASE = "4.0.1"
# The version as a whole token: not 14.0.1, not 4.0.10; v4.0.1 and "4.0.1." count.
LATER_RELEASE_TOKEN = re.compile(r"(?<![\d.])4\.0\.1(?!\.?\d)")
# Same two forms as check_scope_acceptance.py PRERELEASE_400, these notes being
# 4.0.0's; any other version or suffix, build metadata included, is held to the
# final-tag rule.
PRERELEASE_TAG = re.compile(r"^v4\.0\.0-(beta|rc)\.\d+$")
# ATX headings: up to three spaces of indent, optional closing hashes.
HEADING = re.compile(r"^ {0,3}##[ \t]+known issues(?:[ \t]+#*)?[ \t]*$", re.IGNORECASE)
SECTION_END = re.compile(r"^#{1,2}(?:[ \t]|$)")
# Setext: a paragraph line underlined with = (level 1) or - (level 2). A list
# item, indented code, an ATX heading, a quote, a fence or a thematic break
# cannot be one, and after a blank line the underline is a thematic break.
UNDERLINE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
NOT_A_PARAGRAPH = re.compile(
    r"^(?: {4}|\t| {0,3}(?:(?:[-+*]|\d+[.)]|#{1,6})(?:[ \t]|$)|>|```|~~~"
    r"|([-*_])[ \t]*(?:\1[ \t]*){2,}$))"
)
# A fenced block's lines are text, never section ends; it closes on a run of
# the same character at least as long as the one that opened it. A backtick
# run followed by another backtick is an inline span, not a fence.
FENCE = re.compile(r"^ {0,3}(`{3,}(?=[^`]*$)|~{3,})")
# HTML blocks that run across blank lines (CommonMark types 1-5): their lines
# are text too, up to the line that holds the closer.
HTML_BLOCKS = tuple(
    (re.compile(opener, re.IGNORECASE), re.compile(closer, re.IGNORECASE))
    for opener, closer in (
        (r"^ {0,3}<(?:pre|script|style|textarea)(?:[ \t>]|$)", r"</(?:pre|script|style|textarea)>"),
        (r"^ {0,3}<!--", r"-->"),
        (r"^ {0,3}<\?", r"\?>"),
        (r"^ {0,3}<![a-z]", r">"),
        (r"^ {0,3}<!\[CDATA\[", r"\]\]>"),
        # Any other tag opens a block that runs to the next blank line.
        (r"^ {0,3}</?[a-z]", r"\A\s*\Z"),
    )
)
# A link reference definition is not paragraph text, so it is never a heading;
# any line that opens with a bracket is read as one.
REFERENCE = re.compile(r"^ {0,3}\[")


def starts_section(lines, i):
    """True when line i opens a Known issues section.

    Liberal on purpose, and checked before fences and HTML blocks: a doubtful
    start only makes the gate read more. A setext start is a title of one or
    two lines over a dash underline, so a wrapped title still counts.
    """
    if HEADING.match(lines[i]):
        return True
    underline = UNDERLINE.match(lines[i + 1]) if i + 1 < len(lines) else None
    if not underline or underline.group(1)[0] != "-" or not lines[i].strip():
        return False
    two = lines[i - 1] + " " + lines[i] if i else lines[i]
    return "known issues" in (" ".join(text.split()).lower() for text in (lines[i], two))


def ends_section(lines, i):
    """True when the setext heading on line i may end a section.

    Stop rule: this is a line reader, not a Markdown parser, so it does not try
    to decide every form. A section ends only on a plain form: an ATX # or ##
    at column 0, or one line of paragraph text at column 0 after a blank line,
    neither inside a fence or HTML block, and the text not opening with a
    bracket. Every other form stays section text, so the gate can only read
    too much, never too little. Starts stay liberal: starts_section decides
    them.
    """
    line = lines[i]
    return (
        not line[:1].isspace()
        and not REFERENCE.match(line)
        and i > 0
        and not lines[i - 1].strip()
    )


def setext_level(line, underline):
    """1 or 2 when `line` over `underline` is a setext heading, else 0."""
    match = UNDERLINE.match(underline)
    if not match or not line.strip() or NOT_A_PARAGRAPH.match(line):
        return 0
    return 1 if match.group(1)[0] == "=" else 2


def known_issues(text):
    """Every Known issues section's lines, each up to the next level 1-2 heading."""
    lines = text.splitlines()
    body, inside, underline, fence, block = [], False, False, "", None
    for i, line in enumerate(lines):
        if starts_section(lines, i):
            inside, underline = True, not HEADING.match(line)
            continue
        if underline:
            underline = False
            continue
        start = 0
        if not block and not fence:
            for opener, closer in HTML_BLOCKS:
                found = opener.match(line)
                if found:
                    block, start = closer, found.end()
                    break
        if block:
            if block.search(line, start):
                block = None
            if inside:
                body.append(line)
            continue
        opener = FENCE.match(line)
        if fence or opener:
            run = opener.group(1) if opener else ""
            if not fence:
                fence = run
            elif run[:1] == fence[0] and len(run) >= len(fence) and line.strip() == run:
                fence = ""
            if inside:
                body.append(line)
            continue
        level = setext_level(line, lines[i + 1] if i + 1 < len(lines) else "")
        if SECTION_END.match(line) or (level and ends_section(lines, i)):
            inside, underline = False, bool(level)
        elif inside:
            body.append(line)
    return body


def is_prerelease_tag(tag):
    """True only for a v4.0.0-beta.N or v4.0.0-rc.N tag."""
    return bool(PRERELEASE_TAG.match(tag))


def problems(section, release):
    found = [
        f"Known issues names {LATER_RELEASE}: {line.strip()}"
        for line in section
        if LATER_RELEASE_TOKEN.search(line)
    ]
    content = [line for line in section if line.strip()]
    if release and content:
        found.append(
            f"Known issues is not empty at a tag ({len(content)} lines): "
            "fix them or remove the section before tagging"
        )
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notes", default=DEFAULT_NOTES)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--release", action="store_true")
    parser.add_argument(
        "--tag",
        default="",
        help="tag being released; falls back to $GITHUB_REF_NAME when empty",
    )
    args = parser.parse_args(argv)
    tag = args.tag.strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    try:
        text = pathlib.Path(args.notes).read_text(encoding="utf-8")
    except OSError as err:
        print(f"cannot read {args.notes}: {err}", file=sys.stderr)
        return 1
    found = problems(known_issues(text), args.release and not is_prerelease_tag(tag))
    for problem in found:
        print(problem, file=sys.stderr)
    if not found:
        print(f"Known issues gate OK ({args.notes})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
