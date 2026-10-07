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
import html
import os
import pathlib
import re
import sys

DEFAULT_NOTES = "docs/release/v4.0.0-release-notes-DRAFT.md"
THIS_RELEASE = (4, 0, 0)
# A version of this product as a whole token, major 4 or 5 (14.0.1 or a Node
# 20.1 is another product's): any later than 4.0.0 is a deferral, 4.0.1,
# 4.0.10, 4.1 and 5.0 alike. A pre-release or build suffix of 4.0.0 is not,
# nor a number inside one (4.0.0+build-5.1, see IN_SUFFIX). Other 4.x/5.x numbers (a model
# version, a size) read as deferrals too: a false red, reworded away.
VERSION_TOKEN = re.compile(r"(?<![\w.])v?([45])\.(\d+)(?:\.(\d+))?(?!\d|\.\d)")
# Same two forms as check_scope_acceptance.py PRERELEASE_400, these notes being
# 4.0.0's; any other version or suffix, build metadata included, is held to the
# final-tag rule.
# Text that ends inside a version's pre-release or build suffix.
# The suffix must hold a letter: 4.0.0-4.0.1 is a range, not a suffix.
IN_SUFFIX = re.compile(r"\d\.\d+\.\d+[-+][0-9a-z.-]*[a-z][0-9a-z.-]*$", re.IGNORECASE)
PRERELEASE_TAG = re.compile(r"^v4\.0\.0-(beta|rc)\.\d+$")
# ATX level 1-2 headings: up to three spaces of indent; the title is compared as
# letters only (see title_letters), so no inline Markdown can hide it.
HEADING = re.compile(r"^ {0,3}#{1,2}[ \t]+(.*)$")
# What a title's inline Markdown adds besides its text: HTML comments and
# tags, link targets and reference labels.
INLINE_NOISE = re.compile(r"<!--.*?(?:-->|$)|<[^>]*>|\]\([^)]*\)|\]\[[^\]]*\]")
# The same, for body text: only real tags go, so an autolink's URL, which
# renders, is still scanned.
HIDDEN_MARKUP = re.compile(
    r"<!--.*?(?:-->|$)|</?[A-Za-z][A-Za-z0-9-]*(?:\s[^>]*)?/?>|\]\([^)]*\)|\]\[[^\]]*\]"
)
TITLE = "knownissues"
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


def title_letters(text):
    """The letters `text` renders: entities decoded, inline Markdown dropped,
    and nothing else kept, so markup inside a word cannot split it."""
    return re.sub(r"[^a-z]", "", INLINE_NOISE.sub("", html.unescape(text)).lower())


def is_title(text):
    """True when the letters of `text` hold "knownissues".

    Containment, not an exact match: whatever else the title says only makes
    a doubtful start, and a start fails closed.
    """
    return TITLE in title_letters(text)


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
    if not underline or not lines[i].strip():
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
            above = lines[i - 1] if i else ""
            title = line if TITLE in title_letters(line) else f"{above} {line}"
            if title_letters(title).replace(TITLE, "", 1) or later_releases(title):
                # A start line that says more than the title (a bullet read
                # as one, or a version in an annotation, read from the raw
                # text) is content too, so nothing it says is dropped. A
                # wrapped title is kept whole: both of its lines.
                body.append(title)
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
    """The versions `line` renders that are later than this release.

    Markdown decides what renders (a code span keeps its markup), so the line
    is read two ways and a version either reading shows counts (fail closed).
    Both decode entities and drop backslash escapes, emphasis and code marks,
    so 4\\.0\\.1 and 4.0.&#49; count. The second also drops inline tags, link
    targets and brackets (tags before decoding, so &lt;b&gt; stays text), so
    4.0.<em>1</em> and 4.0.[1](url) count.
    """
    found = []
    readings = (
        re.sub(r"[\\`*_]", "", html.unescape(line)),
        re.sub(r"[\\`*_\[\]]", "", html.unescape(HIDDEN_MARKUP.sub("", line))),
    )
    for text in readings:
        found += [
            match.group(0)
            for match in VERSION_TOKEN.finditer(text)
            if tuple(int(part or 0) for part in match.groups()) > THIS_RELEASE
            and not IN_SUFFIX.search(text[: match.start()])
            and match.group(0) not in found
        ]
    return found


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
