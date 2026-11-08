#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A cheap pre-filter for clippy's `doc_markdown` lint, which needs a build.

Clippy fails a doc comment that names code without backticks. A full clippy
run is the only real judge, but this check catches the common case in about a
second, before a push: a word with an underscore between letters or digits
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
when it documents an item, field or variant, so text inside a string or macro
input is not read as a doc; a file that is not UTF-8 is skipped.

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
FENCE = re.compile(r"^\s*(```|~~~)")
# Shapes this check does not parse; a paragraph holding one is skipped whole.
UNPARSED = re.compile(r"<(code|pre|kbd|samp)\b|^\s*>", re.I)
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
        if stripped.startswith(("#[", "//")) and not stripped.startswith("///"):
            continue
        return bool(ITEM.match(line)) and not MOD_DECL.match(line)
    return False


def touches_doc_attr(lines: list[str], run: list[tuple[int, str]], after: int) -> bool:
    """Whether a `#[doc = ...]` attribute sits right before the run or among the
    attributes after it: its text joins the same Markdown, which this check
    does not assemble."""
    first = run[0][0] - 1
    if first > 0 and DOC_ATTR.match(lines[first - 1]):
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
    text, starts, fence, offset, after_blank = [], [], None, 0, True
    for number, body in run:
        marker = FENCE.match(body)
        if fence:
            fence = None if marker and marker.group(1) == fence else fence
            body = ""
        elif marker:
            fence, body = marker.group(1), ""
        elif REF_DEF.match(body):
            body = ""
        elif after_blank and (body.startswith("     ") or body.startswith(" \t")):
            # An indented code block: four spaces past the one after `///`.
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


def scan_text(source: str) -> list[tuple[int, str, bool]]:
    lines = source.splitlines()
    found, run = [], []
    for index, line in enumerate(lines):
        match = DOC.match(line)
        if match:
            run.append((index + 1, match.group(1)))
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
    return 1 if gates else 0


if __name__ == "__main__":
    sys.exit(main())
