#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prove MIK-8144 slice 2 moved `Gateway::run` and its steps unchanged.

Usage: check_moved_run.py <base> <head>

At <head>, `run` lives in server/run.rs and some of its `let` right-hand
sides are calls to methods in server/run_steps.rs. Each call is replaced by
the body of the method it calls, after checking that every argument is the
parameter's own name (`x` or `&x`), so the substitution is exact. A `&`
directly before a step's parameter name is dropped on both sides (Clippy
refuses re-borrowing a reference). A body of
the form `let step = E; Ok(step)` reads back as `E`, and the call's trailing
`.await` and `?` go with it. The rebuilt `run` must equal <base>'s, token for
token, in order. The rest of server/mod.rs must be unchanged apart from its
`use` lines and the two new `mod` lines. Exit 0 when both hold.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

D = "src/gateway/server/"
_spec = importlib.util.spec_from_file_location(
    "tests_proof", Path(__file__).with_name("check_moved_tests.py"))
tp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tp)
moved = tp.moved


def show(ref: str, path: str) -> str:
    return subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)


def toks(text: str) -> list[str]:
    return moved.reshape(tp.tokens(text))


def block(t: list[str], open_at: int) -> int:
    """Index of the token closing the bracket opened at `open_at`."""
    depth = 0
    for k in range(open_at, len(t)):
        if t[k] in "([{":
            depth += 1
        elif t[k] in ")]}":
            depth -= 1
            if depth == 0:
                return k
    raise AssertionError("unbalanced")


def fn_span(t: list[str], name: str) -> tuple[int, int, int]:
    """(start of `fn`, index of the body's `{`, index of its `}`)."""
    hits = [k for k in range(len(t) - 1) if t[k] == "fn" and t[k + 1] == name]
    assert len(hits) == 1, (name, hits)
    k = hits[0]
    body = next(j for j in range(k, len(t)) if t[j] == "{")
    return k, body, block(t, body)


def steps(head: str) -> dict[str, tuple[list[str], list[str]]]:
    """name -> (parameter names, body tokens) for each method in run_steps.rs."""
    t = toks(show(head, D + "run_steps.rs"))
    out = {}
    for k in range(len(t) - 1):
        if t[k] != "fn":
            continue
        name = t[k + 1]
        _, b, e = fn_span(t, name)
        paren = t.index("(", k)
        params = [t[j - 1] for j in range(paren, block(t, paren)) if t[j] == ":"
                  and t[j - 1] != "self"]
        body = t[b + 1 : e]
        n = len(body)
        if body[:4] == ["let", "step", "=", body[3]] and body[n - 5 :] == [";", "Ok", "(", "step", ")"]:
            body = body[3 : n - 5]
        out[name] = (params, body)
    return out


def unborrow(t: list[str], names: set[str]) -> list[str]:
    """Drop `&` before a name that is a reference parameter of a step. In
    `run` the name was an owned local and was borrowed; in the step it is
    already a reference, and Clippy refuses the extra borrow. Both sides are
    read the same way, so this hides no other change."""
    return [x for k, x in enumerate(t) if not (x == "&" and k + 1 < len(t) and t[k + 1] in names)]


def inline(run: list[str], table: dict) -> list[str]:
    out, k = [], 0
    while k < len(run):
        recv = run[k] in ("self", "Self") and k + 3 < len(run) and run[k + 1] in (".", "::")
        if recv and run[k + 2] in table and run[k + 3] == "(":
            params, body = table[run[k + 2]]
            close = block(run, k + 3)
            args = [a for a in " ".join(run[k + 4 : close]).split(" , ") if a]
            got = [a.removeprefix("& ") for a in args]
            assert got == params, f"{run[k + 2]}: arguments {got} are not its parameters {params}"
            k = close + 1
            if run[k : k + 2] == [".", "await"]:
                k += 2
            if k < len(run) and run[k] == "?":
                k += 1
            out.extend(body)
            continue
        out.append(run[k])
        k += 1
    return out


def without_run(text: str) -> list[str]:
    t = toks(text)
    s, b, e = fn_span(t, "run")
    # back up over `pub async` and outer attributes (`# [ ... ]`)
    while s > 0 and t[s - 1] in ("pub", "async"):
        s -= 1
    while s > 0 and t[s - 1] == "]":
        s = next(j for j in range(s - 1, -1, -1) if t[j] == "#")
    return t[:s] + t[e + 1 :]


def drop_uses_and_mods(t: list[str]) -> list[str]:
    out, k = [], 0
    while k < len(t):
        if t[k] == "use" or (t[k] == "mod" and t[k + 1] in ("run", "run_steps") and t[k + 2] == ";"):
            k = t.index(";", k) + 1
            continue
        out.append(t[k])
        k += 1
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    base, head = sys.argv[1], sys.argv[2]
    bt = toks(show(base, D + "mod.rs"))
    _, bb, be = fn_span(bt, "run")
    base_run = bt[bb : be + 1]
    ht = toks(show(head, D + "run.rs"))
    _, hb, he = fn_span(ht, "run")
    table = steps(head)
    rebuilt = inline(ht[hb : he + 1], table)
    names = {p for params, _ in table.values() for p in params}
    base_run, rebuilt = unborrow(base_run, names), unborrow(rebuilt, names)
    problems = []
    if rebuilt != base_run:
        import difflib
        problems += list(difflib.unified_diff(base_run, rebuilt, "base run", "head run", n=4, lineterm=""))[:60]
    rest_base = drop_uses_and_mods(without_run(show(base, D + "mod.rs")))
    rest_head = drop_uses_and_mods(toks(show(head, D + "mod.rs")))
    if rest_base != rest_head:
        problems.append("server/mod.rs changed outside `run`, its `use` lines and the new `mod` lines")
    if problems:
        print("\n".join(problems))
        return 1
    print(f"run moved unchanged: {len(base_run)} tokens, {len(steps(head))} steps inlined; rest of mod.rs unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
