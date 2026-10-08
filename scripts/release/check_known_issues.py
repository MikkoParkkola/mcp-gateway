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
VERSION_TOKEN = re.compile(r"(?<![\w.])[vV]?([45])\.(\d+)(?:\.(\d+))?(?!\d|\.\d)")
# Same two forms as check_scope_acceptance.py PRERELEASE_400, these notes being
# 4.0.0's; any other version or suffix, build metadata included, is held to the
# final-tag rule.
# Text that ends inside a version's pre-release or build suffix.
# A pre-release suffix must hold a letter (4.0.0-4.0.1 is a range, not a
# suffix); build metadata need not (4.0.0+4.0.1 is a build of 4.0.0).
IN_SUFFIX = re.compile(
    r"\d\.\d+\.\d+(?:-[0-9a-z.-]*[a-z][0-9a-z.-]*|\+[0-9a-z.-]*)$", re.IGNORECASE
)
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
    r"<!--.*?(?:-->|$)|<\?.*?(?:\?>|$)|<!\[CDATA\[.*?(?:\]\]>|$)|<![A-Za-z][^>]*>"
    r"|</?[A-Za-z][A-Za-z0-9-]*(?:\s[^>]*)?/?>|\]\([^)]*\)|\]\[[^\]]*\]"
)
# Raw HTML that can interrupt a paragraph (CommonMark HTML block types 1-6):
# any other tag line inside a paragraph is paragraph text.
BLOCK_HTML = re.compile(
    r"^ {0,3}<(?:[?!]|/?(?:script|pre|style|textarea|address|article|aside|base|"
    r"basefont|blockquote|body|caption|center|col|colgroup|details|dialog|dir|div|"
    r"dl|dt|dd|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|"
    r"header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|"
    r"optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|"
    r"thead|title|tr|track|ul)(?:[ \t]|/?>|$))",
    re.IGNORECASE,
)
# A tag read with quoted attribute values, so a quoted > does not end it. An
# extra reading only: an unbalanced quote defeats it, and the plain one holds.
QUOTED_TAG = re.compile(r"<[A-Za-z/!](?:[^>\"']|\"[^\"]*\"|'[^']*')*>")
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


def title_letters(text, keep="a-z"):
    """The letters (or `keep` characters) `text` renders: entities decoded,
    inline Markdown dropped, and nothing else kept, so markup inside a word
    cannot split it."""
    return re.sub(f"[^{keep}]", "", INLINE_NOISE.sub("", html.unescape(text)).lower())


def title_readings(text, keep="a-z"):
    """title_letters of `text`, as written and with quoted-attribute tags
    dropped first; a title either reading holds counts (fail closed)."""
    return (title_letters(text, keep), title_letters(QUOTED_TAG.sub("", text), keep))


def opens_comment(line):
    """True when `line` leaves an HTML comment open."""
    return line.rfind("<!--") > line.rfind("-->")


def is_text(line):
    """True when `line` can be paragraph text: not blank, and no list, quote,
    heading, fence, HTML block that can interrupt a paragraph, or open
    comment. Indented four columns or more, any line is text: a continuation
    line's markers are literal there."""
    wide = line.expandtabs(4)
    if wide.strip() and len(wide) - len(wide.lstrip()) >= 4:
        return True
    return bool(
        line.strip()
        and not NOT_A_PARAGRAPH.match(line)
        and not FENCE.match(line)
        and not BLOCK_HTML.match(line)
        and not opens_comment(line)
    )


def title_lines(lines, i):
    """The readings of a setext title ending on line i: the line, the line
    joined with the one above, and, when line i is paragraph text, the whole
    run of paragraph text above it (a title may span several lines)."""
    two = lines[i - 1] + " " + lines[i] if i else lines[i]
    if not is_text(lines[i]):
        return (lines[i], two)
    start = i
    while start > 0 and is_text(lines[start - 1]):
        start -= 1
    return (lines[i], two, " ".join(lines[start : i + 1]))


def is_title(text):
    """True when the letters of `text` hold "knownissues".

    Containment, not an exact match: whatever else the title says only makes
    a doubtful start, and a start fails closed. The letters are also read
    with no markup dropped, so text that only looks like a tag (an unclosed
    one renders as text) cannot hide a title; such a start keeps its title
    as content (see known_issues).
    """
    raw = re.sub(r"[^a-z]", "", html.unescape(text).lower())
    return TITLE in raw or any(TITLE in letters for letters in title_readings(text))


def atx_start(line):
    """True when `line` is an ATX level 1-2 Known issues heading."""
    match = HEADING.match(line)
    return bool(match) and is_title(match.group(1))


def starts_section(lines, i):
    """True when line i opens a Known issues section.

    Liberal on purpose, and checked before fences and raw HTML: a doubtful
    start only makes the gate read more. A setext start is a title paragraph
    of any number of lines over a dash underline, so a wrapped title counts.
    """
    if atx_start(lines[i]):
        return True
    underline = UNDERLINE.match(lines[i + 1]) if i + 1 < len(lines) else None
    if not underline or not lines[i].strip():
        return False
    return any(is_title(text) for text in title_lines(lines, i))


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
            # The longest reading that holds the title, so text around it in
            # the same heading is kept.
            # An ATX title is its own line; a setext title the longest
            # reading that holds it, so text above it in the heading is kept.
            atx = atx_start(line)
            title = line if atx else max(
                (t for t in title_lines(lines, i) + (line,) if is_title(t)), key=len
            )
            # Content too: a title with both a code span and a tag (which
            # renders depends on span boundaries this reader does not
            # decide), a title only its letters spell, or leftover letters
            # or digits (an issue number).
            alnum = title_readings(title, "a-z0-9")
            extra = (
                # A list item or quote over a thematic break is no heading.
                (not atx and bool(NOT_A_PARAGRAPH.match(line)))
                or ("`" in title and "<" in title)
                or not any(TITLE in r for r in alnum)
                or any(TITLE in r and r.replace(TITLE, "", 1) for r in alnum)
            )
            if extra or later_releases(title):
                # A start line that says more than the title (a bullet read
                # as one, or a version in an annotation, read from the raw
                # text) is content too, so nothing it says is dropped. A
                # wrapped title is kept whole: every line of it.
                body.append(title)
            # A start line may also open a fence or a comment; its state
            # still changes, or what it hides would read as section ends.
            if FENCE.match(line):
                fence = step_fence(fence, line)
            if HTML.match(line) or opens_comment(line):
                sticky = True
            continue
        if underline:
            underline = False
            continue
        # Raw HTML, or a comment left open after text: either can hide a
        # heading, so the section reads on to the end of the notes.
        if inside and not fence and (HTML.match(line) or opens_comment(line)):
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


def in_range(text, match):
    """True when the version `match` ends a hyphen range (4.0.0-rc.1-4.0.1,
    v4.0.0-rc.1-v4.0.1) rather than sitting in the suffix before it: a
    hyphen, then a whole x.y.z or a v-prefixed version. Never inside build
    metadata: 4.0.0+build-4.0.1 is a build of 4.0.0."""
    before = text[: match.start()]
    suffix = IN_SUFFIX.search(before)
    return (
        bool(suffix)
        and "+" not in suffix.group(0)
        and before.endswith("-")
        and (match.group(3) is not None or match.group(0)[:1] in "vV")
    )


def later_releases(line):
    """The versions `line` renders that are later than this release.

    Markdown decides what renders (a code span keeps its markup), so the line
    is read four ways, each with and without tildes, and a version any reading
    shows counts (fail closed).
    All decode entities and drop backslash escapes, emphasis and code marks,
    so 4\\.0\\.1 and 4.0.&#49; count. The second also drops inline tags, link
    targets and brackets (tags before decoding, so &lt;b&gt; stays text), so
    4.0.<em>1</em> and 4.0.[1](url) count. The third first drops tags read
    with quoted attribute values, so 4.0.<em title="a>b">1</em> counts. The
    fourth keeps code-span edges as spaces, so `4.0.0`+`4.0.1` is two versions,
    not a build of 4.0.0.
    """
    found = []
    readings = (
        re.sub(r"[\\`*_]", "", html.unescape(line)),
        re.sub(r"[\\`*_\[\]]", "", html.unescape(HIDDEN_MARKUP.sub("", line))),
        re.sub(
            r"[\\`*_\[\]]", "", html.unescape(HIDDEN_MARKUP.sub("", QUOTED_TAG.sub("", line)))
        ),
        re.sub(r"[\\*_]", "", html.unescape(line)).replace("`", " "),
    )
    # Strikethrough (~ or ~~) may split a version, but a tilde may also mark
    # one (release~4.0.1), so each reading is also read with tildes dropped.
    readings += tuple(text.replace("~", "") for text in readings)
    for text in readings:
        found += [
            match.group(0)
            for match in VERSION_TOKEN.finditer(text)
            if tuple(int(part or 0) for part in match.groups()) > THIS_RELEASE
            and not (IN_SUFFIX.search(text[: match.start()]) and not in_range(text, match))
            and match.group(0) not in found
        ]
    return found


def problems(section, release):
    # A comment, processing instruction, CDATA section or tag may span lines
    # and split a version, so the section is also read with those removed
    # across line breaks: once with comments only, once with all three, as
    # an opener inside a code span would otherwise swallow the rest.
    text = "\n".join(section)
    extra = []
    for hidden in (
        r"<!--.*?(?:-->|$)",
        r"<!--.*?(?:-->|$)|<\?.*?(?:\?>|$)|<!\[CDATA\[.*?(?:\]\]>|$)",
    ):
        joined = re.sub(hidden, "", text, flags=re.S)
        untagged = HIDDEN_MARKUP.sub("", QUOTED_TAG.sub("", joined))
        extra += joined.splitlines() + untagged.splitlines()
    lines = section + [line for line in dict.fromkeys(extra) if line not in section]
    found = [
        f"Known issues names a later release ({', '.join(later)}): {line.strip()}"
        for line in lines
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
