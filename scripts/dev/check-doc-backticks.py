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
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s")
TICKS = re.compile(r"`[^`]*`", re.S)
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


def documents_a_module(lines: list[str], after: int) -> bool:
    """Whether the doc run ending before index `after` sits on `mod name;`,
    past any attributes."""
    for line in lines[after:]:
        if line.strip().startswith("#["):
            continue
        return bool(MOD_DECL.match(line))
    return False


def scan_paragraph(run: list[tuple[int, str]]) -> list[tuple[int, str, bool]]:
    """Each flagged word in one run of `///` lines as (line, word, gate). A
    backtick span may wrap across the run's lines, as in rustdoc."""
    text, starts, fence = [], [], False
    for number, body in run:
        if REF_DEF.match(body):
            body = ""
        elif body.strip().startswith("```"):
            fence, body = not fence, ""
        elif fence:
            body = ""
        starts.append((sum(len(t) + 1 for t in text), number))
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
        if run and not documents_a_module(lines, index):
            found.extend(scan_paragraph(run))
        run = []
    if run:
        found.extend(scan_paragraph(run))
    return found


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def files(base: str | None) -> list[str]:
    if base is None:
        listed = git("ls-files", "src").split()
    else:
        listed = git("diff", "--name-only", "--diff-filter=AM", f"{base}...HEAD").split()
    return [f for f in listed if f.startswith("src/") and f.endswith(".rs") and Path(f).is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="check only .rs files changed since this ref")
    args = parser.parse_args()
    gates = 0
    for path in files(args.base):
        for line, word, gate in scan_text(Path(path).read_text(encoding="utf-8")):
            kind = "error" if gate else "warning (CamelCase)"
            print(f"{path}:{line}: {word}: {kind}: put it in backticks (clippy::doc_markdown)")
            gates += gate
    if gates:
        print(f"{gates} doc comment word(s) clippy::doc_markdown would refuse; put each in backticks")
    return 1 if gates else 0


if __name__ == "__main__":
    sys.exit(main())
