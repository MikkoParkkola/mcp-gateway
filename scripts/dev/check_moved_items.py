#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prove items moved out of server/mod.rs into sibling files unchanged.

Usage: check_moved_items.py [--source <path>] <base> <head> <file>...

<file> names the new files under src/gateway/server/ (for example
background.rs). With `--source <path>`, the items move out of <path> instead
of server/mod.rs, and each <file> is named relative to <path>'s directory. The items of server/mod.rs at <base> must equal, as a
multiset, the items of server/mod.rs and the named files at <head>. Each
method of an `impl Gateway` block counts as an item of its own, so a method
may move between impl blocks. `use` and `mod` lines are not compared (the
compiler checks them). The only differences allowed are the ones a move
makes: a `pub(super)` visibility added to an item or field, and, in a new
file, `super::super::` for what was `super::` (a path one module higher).
Comments and whitespace are ignored. Exit 0 when equal.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

D = "src/gateway/server/"
_spec = importlib.util.spec_from_file_location(
    "tests_proof", Path(__file__).with_name("check_moved_tests.py"))
tp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tp)


def show(ref: str, path: str) -> str:
    return subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)


def split(toks: list[str]) -> list[list[str]]:
    """Top-level items of a token stream (a braced `use` is one item)."""
    out, cur, depth = [], [], 0
    for t in toks:
        cur.append(t)
        if t in "([{":
            depth += 1
        elif t in ")]}":
            depth -= 1
        if depth == 0 and t == ";" and cur == [";"] and out:
            out[-1].append(";")
            cur = []
        elif depth == 0 and t in (";", "}") and not (cur[0] == "#" and t == "}" and cur[-2:] == ["]", "}"]):
            out.append(cur)
            cur = []
    assert not cur and depth == 0, "unbalanced"
    return out


def items(text: str, moved: bool) -> list[str]:
    toks = tp.tokens(text)
    if moved:
        # Token-wise, so a string literal with a space stays one token. A file
        # moved one module down reaches each ancestor through one more
        # `super ::`, so a maximal chain of k >= 2 reads back as k - 1.
        out: list[str] = []
        i = 0
        while i < len(toks):
            k = 0
            while toks[i + 2 * k : i + 2 * k + 2] == ["super", "::"]:
                k += 1
            if k >= 2:
                out += ["super", "::"] * (k - 1)
                i += 2 * k
            else:
                out.append(toks[i])
                i += 1
        toks = out
    toks = tp.moved.reshape(toks)
    found = []
    for it in split(toks):
        s = " ".join(it)
        body = re.sub(r"^(# \[ [^\]]* \] )+", "", s)
        if body.startswith(("use ", "pub ( crate ) use ", "pub use ", "mod ", "pub mod ", "pub ( crate ) mod ")):
            continue
        if body.startswith("impl Gateway {"):
            inner = it[it.index("{") + 1 : -1]
            for m in split(inner):
                found.append("impl Gateway :: " + norm(" ".join(m)))
            continue
        found.append(norm(s))
    return found


def norm(s: str) -> str:
    """Drop the `pub(super)` a move may add (items and struct fields)."""
    return re.sub(r"(^|[({,;\]] )pub \( super \) ", r"\1", s)


def main() -> int:
    args = sys.argv[1:]
    source = D + "mod.rs"
    if args[:1] == ["--source"] and len(args) > 1:
        source, args = args[1], args[2:]
    if len(args) < 3:
        print(__doc__)
        return 2
    base, head, files = args[0], args[1], args[2:]
    here = source.rsplit("/", 1)[0] + "/"
    a = Counter(items(show(base, source), False))
    b = Counter(items(show(head, source), False))
    for f in files:
        b.update(items(show(head, here + f), True))
    problems = [f"only at base: {x[:150]}" for x in sorted((a - b).elements())]
    problems += [f"only at head: {x[:150]}" for x in sorted((b - a).elements())]
    if problems:
        print("\n".join(problems))
        return 1
    moved = sum(sum(1 for _ in items(show(head, here + f), True)) for f in files)
    print(f"items equal: {sum(a.values())} items, {moved} of them moved into {', '.join(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
