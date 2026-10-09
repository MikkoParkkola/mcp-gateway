#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prove MIK-8144 moved server/mod.rs's inline tests into files unchanged.

Usage: check_moved_tests.py <base> <head>

Rebuilds the inline `mod tests { .. }` of `src/gateway/server/mod.rs` at
<head> from its out-of-line children and compares its top-level items with
<base>'s, as a multiset (test order carries no meaning). A child the move
created is either a former inline module (<base> has `mod name {` in the
test module; its body is wrapped back in `mod name { .. }`) or holds items
regrouped one level down (its first `use super::*;` is dropped and its
`super::super::` reads back as `super::`). An `include_str!`/`include!` path in a new child must
start with `../`, which is read back off; a path left as it was would now
name the wrong file and is refused. Everything in mod.rs outside the test
module must be unchanged. Exit 0 when equal; otherwise print the difference.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

MOD = "src/gateway/server/mod.rs"
DIR = "src/gateway/server/tests/"

_spec = importlib.util.spec_from_file_location(
    "moved", Path(__file__).with_name("check_moved_statements.py"))
moved = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(moved)

INCLUDE = re.compile(r'(include(?:_str|_bytes)?!\(\s*)"([^"]*)"')


def show(ref: str, path: str) -> str | None:
    try:
        return subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True,
                                       stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None


def split_tests(text: str) -> tuple[str, str]:
    lines = text.split("\n")
    start = lines.index("mod tests {")
    assert lines[-1] == "" and lines[-2] == "}", "mod tests must close the file"
    return "\n".join(lines[:start]), "\n".join(lines[start + 1 : -2])


# Comments are matched in the same pass as strings, so a `//` or a quote
# inside a multi-line string literal cannot desynchronise either.
LEXEME = re.compile(r"//[^\n]*|/\*.*?\*/|" + moved.TOKEN.pattern, re.S)


CONTINUATION = re.compile(r"\\\n[ \t\n\r]*")


def tokens(text: str) -> list[str]:
    """Code tokens. A string literal is read as the compiler reads it: a
    backslash-newline drops the line break and the next line's leading
    whitespace, so re-indenting a continued string is not a change. A string
    whose lines carry no backslash keeps its indentation and is compared as
    written."""
    return [CONTINUATION.sub("", t) if t.startswith('"') else t
            for t in LEXEME.findall(text) if not t.startswith(("//", "/*"))]


def items(text: str) -> list[str]:
    toks = moved.reshape(tokens(text))
    out, cur, depth = [], [], 0
    for t in toks:
        cur.append(t)
        if t in "([{":
            depth += 1
        elif t in ")]}":
            depth -= 1
        if depth == 0 and t in (";", "}"):
            out.append(" ".join(cur))
            cur = []
    assert not cur and depth == 0, "unbalanced module body"
    return out


def rebuild(ref: str, body: str, base: str, base_body: str) -> tuple[str, list[str]]:
    """The head test module with each new child read back in place."""
    problems, out = [], []
    for line in body.split("\n"):
        m = re.fullmatch(r"    mod (\w+);", line)
        child = show(ref, DIR + f"{m.group(1)}.rs") if m else None
        if not m or show(base, DIR + f"{m.group(1)}.rs") is not None:
            out.append(line)
            continue
        assert child is not None, f"{m.group(1)}.rs missing at {ref}"
        text = child

        def back(match: re.Match) -> str:
            if not match.group(2).startswith("../"):
                problems.append(f"{m.group(1)}.rs: {match.group(0)}\" names a path "
                                "relative to the old file")
                return match.group(0) + '"'
            return f'{match.group(1)}"{match.group(2)[3:]}"'

        text = INCLUDE.sub(back, text)
        if not re.search(rf"^    mod {m.group(1)} {{$", base_body, re.M):
            text = re.sub(r"^use super::\*;$", "", text, count=1, flags=re.M)
            out.append(re.sub(r"(?<![\w:])super::super::", "super::", text))
        else:
            out.append(f"mod {m.group(1)} {{\n{text}\n}}")
    return "\n".join(out), problems


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    base, head = sys.argv[1], sys.argv[2]
    base_rest, base_tests = split_tests(show(base, MOD))
    head_rest, head_tests = split_tests(show(head, MOD))
    rebuilt, problems = rebuild(head, head_tests, base, base_tests)
    if base_rest != head_rest:
        problems.append("mod.rs changed outside its test module")
    a, b = Counter(items(base_tests)), Counter(items(rebuilt))
    for item in sorted((a - b).elements()):
        problems.append("only at base: " + item[:160])
    for item in sorted((b - a).elements()):
        problems.append("only at head: " + item[:160])
    if problems:
        print("\n".join(problems))
        return 1
    print(f"moved test items equal: {sum(a.values())} items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
