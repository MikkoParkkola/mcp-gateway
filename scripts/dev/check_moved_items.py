#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prove items moved out of one Rust file into others unchanged.

Usage: check_moved_items.py [--source <path>] [--impl <Type>]... [--also <path>]... <base> <head> <file>...

The items move out of <path> (default src/gateway/server/mod.rs) into each
<file>, named relative to <path>'s directory (for example background.rs, or
backend/definition_access.rs). The items of <path> and of every <file> that
already existed at <base> must equal, as a multiset, the items of <path> and
the named files at <head>. Each method of an `impl <Type>` block (default
`Gateway`; repeat `--impl` for more types) counts as an item of its own, so a
method may move between impl blocks. `use` and `mod` lines are not compared
(the compiler checks them). The only differences allowed are the ones a move
makes: a `pub(super)` visibility added to an item or field, and, in a named
file, one `super::` less on each `super::` chain (a path one module higher).
An inline `mod name { .. }` is opened and its items compared one module down,
the way the same items read in a file module.

A source may be gone at <head> (it became a directory module): it then has no
items there, and `<stem>/mod.rs`, named as a <file>, is read as the same
module. `--also <path>` (repository-relative) names a file that held some of
the items at <base> under another path, such as a child module renamed into
the new directory; it is read like a named <file>.

Comments and whitespace are ignored; literals are compared whole. Exit 0 when
equal, 1 on a difference, 2 on a usage error.
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


def lift(toks: list[str]) -> list[str]:
    """Read code one module down as if it were one module up: each module
    below reaches an ancestor through one more `super ::`, so a maximal chain
    of k >= 2 reads back as k - 1. Token-wise, so a literal stays whole."""
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
    return out


INLINE_MOD = re.compile(r"^(pub (\( [\w ]+ \) )?)?mod \w+ \{")


def items(text: str, moved: bool, impls: tuple[str, ...] = ("Gateway",)) -> list[str]:
    toks = tp.tokens(text)
    if moved:
        toks = lift(toks)
    return found_in(tp.moved.reshape(toks), impls)


def found_in(toks: list[str], impls: tuple[str, ...]) -> list[str]:
    found = []
    for it in split(toks):
        s = " ".join(it)
        body = re.sub(r"^(# \[ [^\]]* \] )+", "", s)
        if INLINE_MOD.match(body):
            # An inline module's items, one module down: compared with the
            # same items in a file module, which is read lifted the same way.
            found += found_in(lift(it[it.index("{") + 1 : -1]), impls)
            continue
        if body.startswith(("use ", "pub ( crate ) use ", "pub use ", "mod ", "pub mod ", "pub ( crate ) mod ")):
            continue
        owner = next((i for i in impls if body.startswith(f"impl {i} {{")), None)
        if owner:
            inner = it[it.index("{") + 1 : -1]
            for m in split(inner):
                found.append(f"impl {owner} :: " + norm(" ".join(m)))
            continue
        found.append(norm(s))
    return found


def norm(s: str) -> str:
    """Drop the `pub(super)` a move may add (items and struct fields)."""
    return re.sub(r"(^|[({,;\]] )pub \( super \) ", r"\1", s)


def exists(ref: str, path: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{ref}:{path}"],
                          capture_output=True).returncode == 0


def main() -> int:
    args = sys.argv[1:]
    source, impls, also = D + "mod.rs", [], []
    while args[:1] in (["--source"], ["--impl"], ["--also"]) and len(args) > 1:
        flag, value, args = args[0], args[1], args[2:]
        if flag == "--source":
            source = value
        elif flag == "--impl":
            impls.append(value)
        else:
            also.append(value)
    if len(args) < 3:
        print(__doc__)
        return 2
    impls_t = tuple(impls) or ("Gateway",)
    base, head, files = args[0], args[1], args[2:]
    here = source.rsplit("/", 1)[0] + "/"
    # `x.rs` becoming `x/mod.rs` keeps its module: read it unlifted.
    own_dir = source[: -len(".rs")] + "/mod.rs" if source.endswith(".rs") else None

    def read(ref: str, path: str, moved: bool) -> list[str]:
        return items(show(ref, path), moved, impls_t) if exists(ref, path) else []

    if not exists(base, source):
        print(f"{source} does not exist at {base}")
        return 2
    a = Counter(read(base, source, False))
    b = Counter(read(head, source, False))
    for f in files:
        moved = here + f != own_dir
        a.update(read(base, here + f, moved))
        b.update(read(head, here + f, moved))
    for f in also:
        a.update(read(base, f, True))
    problems = [f"only at base: {x[:150]}" for x in sorted((a - b).elements())]
    problems += [f"only at head: {x[:150]}" for x in sorted((b - a).elements())]
    if problems:
        print("\n".join(problems))
        return 1
    moved_n = sum((b - Counter(read(head, source, False))).values())
    print(f"items equal: {sum(a.values())} items, {moved_n} of them in {', '.join(files)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
