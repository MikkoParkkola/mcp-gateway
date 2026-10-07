# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Known issues gate for the release notes.

--check (every PR): the "## Known issues" section must not name a later
release. Nothing in 4.0 is deferred, so a "fixed in 4.0.1" (or 4.1, or 5.0)
line is a promise the release plan no longer makes.

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
THIS_RELEASE = (4, 0, 0)
# A version of this product as a whole token, major 4 or 5 (14.0.1 or a Node
# 20.1 is another product's): any later than 4.0.0 is a deferral, 4.0.1,
# 4.0.10, 4.1 and 5.0 alike. A pre-release or build suffix of 4.0.0 is not.
VERSION_TOKEN = re.compile(r"(?<![\d.])v?([45])\.(\d+)(?:\.(\d+))?(?!\d|\.\d)")
# Same two forms as check_scope_acceptance.py PRERELEASE_400, these notes being
# 4.0.0's; any other version or suffix, build metadata included, is held to the
# final-tag rule.
PRERELEASE_TAG = re.compile(r"^v4\.0\.0-(beta|rc)\.\d+$")
# ATX level 1-2 headings: up to three spaces of indent; the title is compared as
# words only (see is_title), so closing hashes and inline Markdown never hide it.
HEADING = re.compile(r"^ {0,3}#{1,2}[ \t]+(.*)$")
# What a title's inline Markdown adds besides its words: HTML tags and
# comments, and link targets.
INLINE_NOISE = re.compile(r"<[^>]*>|\]\([^)]*\)")
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
# Raw HTML (a tag, comment or declaration at the start of a line). Its block
# rules nest without end, so a section that holds any never ends: the gate
# reads it to the end of the notes. An autolink (<https://...>, <a@b.c>) is
# not HTML.
HTML = re.compile(
    r"^ {0,3}<(?![a-z][a-z0-9+.-]{1,31}:[^\s<>]*>|[^\s<>@]+@[^\s<>]+>)[a-z/!?]",
    re.IGNORECASE,
)
# A link reference definition is not paragraph text, so it is never a heading;
# any line that opens with a bracket is read as one.
REFERENCE = re.compile(r"^ {0,3}\[")


def is_title(text):
    """True when `text`, reduced to its words, reads "known issues"."""
    words = re.sub(r"[^a-z]+", " ", INLINE_NOISE.sub(" ", text).lower()).split()
    return words == ["known", "issues"]


def atx_start(line):
    """True when `line` is an ATX level 1-2 Known issues heading."""
    match = HEADING.match(line)
    return bool(match) and is_title(match.group(1))


def starts_section(lines, i):
    """True when line i opens a Known issues section.

    Liberal on purpose, and checked before fences and raw HTML: a doubtful
    start only makes the gate read more. A setext start is a title of one or
    two lines over a dash underline, so a wrapped title still counts.
    """
    if atx_start(lines[i]):
        return True
    underline = UNDERLINE.match(lines[i + 1]) if i + 1 < len(lines) else None
    if not underline or underline.group(1)[0] != "-" or not lines[i].strip():
        return False
    two = lines[i - 1] + " " + lines[i] if i else lines[i]
    return is_title(lines[i]) or is_title(two)


def ends_section(lines, i):
    """True when the setext heading on line i may end a section.

    Stop rule: this is a line reader, not a Markdown parser, so it does not try
    to decide every form. A section ends only on a plain form: an ATX # or ##
    at column 0, or one line of paragraph text at column 0 after a blank line,
    never inside a fence and never after raw HTML in the section, and the text
    not opening with a bracket. Every other form stays section text, so the
    gate can only read too much, never too little. Starts stay liberal:
    starts_section decides them.
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


def step_fence(fence, line):
    """The open fence run after `line`: opened, kept, or closed ("")."""
    opener = FENCE.match(line)
    run = opener.group(1) if opener else ""
    if not fence:
        return run
    if run[:1] == fence[0] and len(run) >= len(fence) and line.strip() == run:
        return ""
    return fence


def known_issues(text):
    """Every Known issues section's lines, each up to the next plain level 1-2
    heading (see ends_section), or to the end of the notes once it holds raw
    HTML."""
    lines = text.splitlines()
    body, inside, underline, fence, sticky = [], False, False, "", False
    for i, line in enumerate(lines):
        if starts_section(lines, i):
            inside, underline = True, not atx_start(line)
            continue
        if underline:
            underline = False
            continue
        if inside and not fence and HTML.match(line):
            sticky = True
        if fence or FENCE.match(line):
            fence = step_fence(fence, line)
            if inside:
                body.append(line)
            continue
        level = setext_level(line, lines[i + 1] if i + 1 < len(lines) else "")
        if sticky:
            body.append(line)
        elif SECTION_END.match(line) or (level and ends_section(lines, i)):
            inside, underline = False, bool(level)
        elif inside:
            body.append(line)
    return body


def is_prerelease_tag(tag):
    """True only for a v4.0.0-beta.N or v4.0.0-rc.N tag."""
    return bool(PRERELEASE_TAG.match(tag))


def later_releases(line):
    """The versions in `line` later than this release."""
    return [
        match.group(0)
        for match in VERSION_TOKEN.finditer(line)
        if tuple(int(part or 0) for part in match.groups()) > THIS_RELEASE
    ]


def problems(section, release):
    found = [
        f"Known issues names a later release ({', '.join(later)}): {line.strip()}"
        for line in section
        if (later := later_releases(line))
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
