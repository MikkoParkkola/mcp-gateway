#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A cheap pre-filter for clippy's `doc_markdown` lint, which needs a build.

Clippy fails a doc comment that names code without backticks. A full clippy
run is the only real judge, but this check catches the common case in a few
seconds, before a push: a word with an underscore between letters or digits
(`start_entry`, `src/mutant_macro.rs`), or with `::` (`crate::clock`), in an
outer `///` doc comment under `src/`, outside backticks, links, link
reference definitions and code fences. That is a gate: it exits 1.

CamelCase words (`ETag`, `LocalFailure`) are only a warning. Clippy flags
them too, but it accepts a list of known words (`PowerShell`, `DevOps`) that
this check cannot reproduce exactly, so gating on them would block pushes
clippy lets through.

Not checked, because clippy passes underscore words in them on the release
line today: `//!` inner docs (out-of-line modules), docs on a `mod name;`
declaration, and files outside `src/`. A word joined to `-` or holding `://`
is skipped too (a line range after a path, a URL), as clippy skips it.

A false block stops every push, so whatever this check cannot read the way
clippy's Markdown parser does is skipped rather than guessed: code spans of
any backtick length, ``` and ~~~ fences and indented code are code; a
paragraph holding HTML code tags or a blockquote, or touching a
`#[doc = ...]` attribute, is skipped whole; a run of `///` lines counts only
when it documents an item, field or variant, and a line that starts inside a
string literal or block comment is never a doc; a file that is not UTF-8 is
skipped.

    check-doc-backticks.py               every .rs file under src/
    check-doc-backticks.py --base REF    only files changed since REF
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DOC = re.compile(r"^\s*///(?!/)(.*)$")
MOD_DECL = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*;")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:")
# A code span: a run of backticks closed by a run of the same length.
TICKS = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)", re.S)
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
# Shapes this check does not parse; a paragraph holding one is skipped whole.
UNPARSED = re.compile(r"<(code|pre|kbd|samp)\b|^\s*>|\\`", re.I)
DOC_ATTR = re.compile(r"^\s*#!?\[doc\s*=")
VIS = r"(pub(\([^)]*\))?\s+)?"
# The line a doc run documents: an item, a field or an enum variant.
ITEM = re.compile(
    r"^\s*" + VIS + r"((async|const|unsafe|default|extern(\s+\"[^\"]*\")?)\s+)*"
    r"(fn|struct|enum|union|trait|impl|type|const|static|mod|use|macro_rules!)\b"
    r"|^\s*" + VIS + r"[A-Za-z_]\w*\s*:[^:]"
    r"|^\s*[A-Z]\w*\s*(,|\{|\(|=|$)"
    r"|^\s*\w+!\s*[\(\{\[]"
)
LINKS = re.compile(r"\[[^\]]*\]\([^)]*\)|<https?://[^>]*>|\[[^\]]*\]", re.S)
UNDERSCORE = re.compile(r"[A-Za-z0-9]_[A-Za-z0-9]")
TRIM = "()[]{}<>,.;:!?'\"*"
# Clippy's default doc-valid-idents: words it accepts bare (a subset).
VALID = set(
    """KiB MiB GiB TiB PiB EiB DirectX ECMAScript GPLv2 GPLv3 GitHub GitLab IPv4 IPv6
    ClojureScript CoffeeScript JavaScript PostScript PureScript TypeScript WebAssembly
    NaN NaNs OAuth GraphQL OCaml OpenAL OpenDNS OpenGL OpenMP OpenSSH OpenSSL
    OpenStreetMap OpenTelemetry OpenType WebGL WebGL2 WebGPU WebRTC WebSocket
    WebTransport WebP OpenExr YCbCr sRGB TensorFlow TrueType iOS macOS FreeBSD NetBSD
    OpenBSD TeX LaTeX BibTeX BibLaTeX MinGW CamelCase PowerShell DevOps""".split()
)


def is_camel_case(word: str) -> bool:
    """Clippy's shape: starts uppercase; a trailing `s` aside, alphanumeric with
    two or more capitals and at least one lowercase letter."""
    if not word or not word[0].isupper() or word in VALID or word[:-1] in VALID:
        return False
    stem = word[:-1] if word.endswith("s") else word
    return stem.isalnum() and sum(c.isupper() for c in stem) >= 2 and any(c.islower() for c in stem)


def documents_an_item(lines: list[str], after: int) -> bool:
    """Whether the doc run ending before index `after` documents an item, a
    field or a variant (past attributes and plain comments), and not a
    `mod name;` declaration. Lines in a string or macro input fail this."""
    for line in lines[after:]:
        stripped = line.strip()
        if stripped.startswith("#[") or (stripped.startswith("//") and not DOC.match(line)):
            continue
        return bool(ITEM.match(line)) and not MOD_DECL.match(line)
    return False


def touches_doc_attr(lines: list[str], run: list[tuple[int, str]], after: int) -> bool:
    """Whether a `#[doc = ...]` attribute sits right before the run or among the
    attributes after it: its text joins the same Markdown, which this check
    does not assemble."""
    for line in reversed(lines[: run[0][0] - 1]):
        if not line.strip().startswith("#["):
            break
        if DOC_ATTR.match(line):
            return True
    for line in lines[after:]:
        if not line.strip().startswith("#["):
            return False
        if DOC_ATTR.match(line):
            return True
    return False


def scan_paragraph(run: list[tuple[int, str]]) -> list[tuple[int, str, bool]]:
    """Each flagged word in one run of `///` lines as (line, word, gate). A
    backtick span may wrap across the run's lines, as in rustdoc."""
    if any(UNPARSED.search(body) for _, body in run):
        return []
    # rustdoc strips the indent all the run's lines share before Markdown sees it.
    # A tab-led line after a blank one is read as code: how rustdoc counts that
    # tab against the shared indent is not settled here, so it never blocks.
    tabbed = {number for number, body in run if body.lstrip(" ").startswith("\t")}
    run = [(number, body.expandtabs(4)) for number, body in run]
    indents = [len(body) - len(body.lstrip(" ")) for _, body in run if body.strip()]
    common = min(indents, default=0)
    text, starts, fence, offset, after_blank = [], [], None, 0, True
    for number, body in run:
        body = body[common:]
        marker = FENCE.match(body)
        if fence:
            closes = marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence)
            fence = None if closes else fence
            body = ""
        elif marker:
            fence, body = marker.group(1), ""
        elif REF_DEF.match(body):
            body = ""
        elif after_blank and body.strip() and (number in tabbed or len(body) - len(body.lstrip(" ")) >= 4):
            # An indented code block: four columns past the run's shared indent.
            body = ""
        else:
            after_blank = False
        if not body.strip() and not fence:
            after_blank = True
        starts.append((offset, number))
        offset += len(body) + 1
        text.append(body)
    joined = "\n".join(text)
    blank = lambda m: re.sub(r"[^\n]", " ", m.group(0))
    joined = LINKS.sub(blank, TICKS.sub(blank, joined))
    found = []
    for match in re.finditer(r"\S+", joined):
        word = match.group(0).strip(TRIM)
        if "-" in word or "://" in word:
            continue
        gate = bool(UNDERSCORE.search(word)) or "::" in word
        if gate or is_camel_case(word):
            line = max(s for s in starts if s[0] <= match.start())[1]
            found.append((line, word, gate))
    return found


RAW_OPEN = re.compile(r'b?r(#*)"')
CHAR_LIT = re.compile(r"'(\\.[^']{0,8}|[^'\\])'")
NEXT_SPECIAL = re.compile(r"[\"'/br\n]")


def opaque_lines(source: str) -> set[int]:
    """Indexes of lines that start inside a string literal or a block comment,
    where a `///` is text, not a doc comment. Character literals and lifetimes
    are told apart so a `'"'` does not open a string."""
    opaque, line, i, n = set(), 0, 0, len(source)
    state, depth, hashes = None, 0, 0
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            if state in ("str", "raw", "block"):
                opaque.add(line)
            i += 1
            continue
        if state == "str":
            # An escaped newline still ends a line: step onto it, not past it.
            i += 2 if c == "\\" and source[i + 1 : i + 2] != "\n" else 1
            if c == '"':
                state = None
            continue
        if state == "raw":
            if c == '"' and source.startswith("#" * hashes, i + 1):
                state, i = None, i + 1 + hashes
            else:
                i += 1
            continue
        if state == "block":
            if source.startswith("/*", i):
                depth, i = depth + 1, i + 2
            elif source.startswith("*/", i):
                depth, i = depth - 1, i + 2
                state = None if depth == 0 else state
            else:
                i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
            continue
        if source.startswith("/*", i):
            state, depth, i = "block", 1, i + 2
            continue
        raw = RAW_OPEN.match(source, i) if c in "br" else None
        if raw and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_")):
            state, hashes, i = "raw", len(raw.group(1)), raw.end()
            continue
        if c == '"':
            state, i = "str", i + 1
            continue
        if c not in "br'/":
            # Nothing else opens a literal or a comment: jump to the next candidate.
            nxt = NEXT_SPECIAL.search(source, i + 1)
            i = nxt.start() if nxt else n
            continue
        char = CHAR_LIT.match(source, i) if c == "'" else None
        i = char.end() if char else i + 1
    return opaque


def scan_text(source: str) -> list[tuple[int, str, bool]]:
    lines = source.splitlines()
    opaque = opaque_lines(source)
    found, run = [], []
    for index, line in enumerate(lines):
        match = None if index in opaque else DOC.match(line)
        if match:
            run.append((index + 1, match.group(1)))
            continue
        if run and index not in opaque and line.strip().startswith("//"):
            # A plain comment between doc lines: rustdoc joins the docs around it.
            continue
        if run and documents_an_item(lines, index) and not touches_doc_attr(lines, run, index):
            found.extend(scan_paragraph(run))
        run = []
    return found


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def files(base: str | None) -> list[str]:
    if base is None:
        listed = git("ls-files", "-z", "src").split("\0")
    else:
        listed = git("diff", "-z", "--name-only", "--diff-filter=AMR", f"{base}...HEAD").split("\0")
    return [f for f in listed if f.startswith("src/") and f.endswith(".rs") and Path(f).is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="check only .rs files changed since this ref")
    args = parser.parse_args()
    gates = 0
    for path in files(args.base):
        try:
            source = Path(path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            print(f"{path}: skipped, not UTF-8 (the compiler judges it)")
            continue
        for line, word, gate in scan_text(source):
            kind = "error" if gate else "warning (CamelCase)"
            print(f"{path}:{line}: {word}: {kind}: put it in backticks (clippy::doc_markdown)")
            gates += gate
    if gates:
        print(f"{gates} doc comment word(s) clippy::doc_markdown would refuse; put each in backticks")
        print(
            "If clippy accepts the line (this check is a text approximation of it), put the word "
            "in backticks anyway, which clippy also accepts, and report the line against "
            "scripts/dev/check-doc-backticks.py so the check can be narrowed."
        )
    return 1 if gates else 0


if __name__ == "__main__":
    sys.exit(main())
