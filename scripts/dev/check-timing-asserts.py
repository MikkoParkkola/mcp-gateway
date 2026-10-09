#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Refuse wall-clock upper bounds under 5 s in tests (MIK-8222, timing-flakes).

A test that tells two outcomes apart by elapsed time against a short window
goes red on a loaded runner. Wait on an event, or use `test_wait`, instead.

Lexical by design: the threat is a careless timing oracle, not an adversary.
A window built at run time is refused (fail closed); a spelling this misses is
an accepted miss. 5 s is a policy cutoff: `Duration::from_secs(5)` is already
the tree's hang bound, so a window at or over it is read as a hang guard.

The allowlist is shrink-only: with `--base <ref>` a row absent from the list
at `ref` fails. The comparison is skipped only when `ref` has no list.

Usage:
    check-timing-asserts.py               # check the tree
    check-timing-asserts.py --base <ref>  # also refuse rows added since <ref>
"""

from __future__ import annotations

import argparse
import bisect
import functools
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

THRESHOLD_S = 5.0
ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path(__file__).with_name("timing-asserts-allowlist.tsv")
SCANNED = ("src", "tests", "crates")

ASSERT = re.compile(r"\b(?:debug_)?assert(_eq|_ne)?!\s*\(")
FN = re.compile(r"\bfn\s+(\w+)")
UNITS = {"secs": 1.0, "millis": 1e-3, "micros": 1e-6, "nanos": 1e-9}
DURATION = re.compile(r"(?:std::time::|tokio::time::)?Duration::from_(secs|millis|micros|nanos)\(\s*([\d_]+)\s*\)")


class Finding(NamedTuple):
    path: str
    fn: str
    assertion: str
    line: int
    window: float | None
    rule: str

    def __str__(self) -> str:
        window = "?" if self.window is None else f"{self.window:g} s"
        return f"FAIL {self.path}:{self.line} ({self.fn}): {self.rule}, window {window}: {self.assertion}"


class Row(NamedTuple):
    path: str
    fn: str
    assertion: str
    reason: str


RAW_OPEN = re.compile(r'b?r(#*)"')
CHAR = re.compile(r"'(?:\\.|[^\\'])'")


SPECIAL = re.compile(r'//|/\*|b?r#*"|"|\'')


@functools.lru_cache(maxsize=None)
def blank_strings_and_comments(text: str) -> str:
    """`text` with comments and string literals blanked, newlines kept.

    Strings become `""`, so a message naming `elapsed()` reads as nothing.
    Jumps from one comment or literal opener to the next, so the plain text
    between them is copied in one slice rather than character by character.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        m = SPECIAL.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        k, tok = m.start(), m.group()
        out.append(text[i:k])
        i = k
        if tok == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif tok == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif tok not in ('"', "'"):
            quote = k + len(tok) - 1
            if k > 0 and (text[k - 1].isalnum() or text[k - 1] == "_"):
                # An identifier ending in `r` / `b` before a quote: not a raw
                # prefix. Copy it; the quote opens a plain string next round.
                out.append(text[k:quote])
                i = quote
                continue
            close = '"' + RAW_OPEN.match(text, k).group(1)
            j = text.find(close, m.end())
            j = n if j < 0 else j + len(close)
            out.append('""' + "\n" * text.count("\n", i, j))
            i = j
        elif tok == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append('""' + "\n" * text.count("\n", i, j))
            i = j + 1
        elif char := CHAR.match(text, i):
            out.append("' '")
            i = char.end()
        else:
            out.append("'")
            i += 1
    return "".join(out)


def calls(code: str):
    """(offset, is_equality, argument text) for each assert call, bracket-matched."""
    for m in ASSERT.finditer(code):
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[i], 0)
            i += 1
        yield m.start(), m.group(1) is not None, code[m.end() : i - 1]


def split_top(text: str, seps: tuple[str, ...]) -> list[tuple[str, str]]:
    """Split at separators outside brackets: [(separator before part, part)]."""
    parts, depth, start, prev, i = [], 0, 0, "", 0
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            sep = next((s for s in seps if text.startswith(s, i)), None)
            # `::<` and `->` / `=>` are not comparisons; `<<` and `>>` are shifts.
            if sep and not (sep in "<>" and (text[i - 1 : i] in "-=:<>" or text[i + 1 : i + 2] in "<>")):
                parts.append((prev, text[start:i]))
                prev, i = sep, i + len(sep)
                start = i
                continue
        i += 1
    parts.append((prev, text[start:]))
    return parts


NUMBER = re.compile(r"^[\d_]+(?:\.[\d_]+)?(?:_?(?:u|i|f)\d+|usize)?$")
DURATION_F = re.compile(r"^(?:std::time::|tokio::time::)?Duration::from_secs_f(?:32|64)\(\s*([\d_.]+)\s*\)$")
CONST = re.compile(r"\b(pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*[^=;]+=\s*([^;]+);")


class Scope(NamedTuple):
    """What a name can resolve to: fn-local lets, file consts, then tree consts.

    A const from another file is found the way Rust finds it, or not at all:
    through a qualifier (`pins::B`) or a `use` path naming its module, or,
    unqualified, from an ancestor module (`use super::*`). It is evaluated in
    its own file, so `B = A` reads that file's `A`. Two candidate
    definitions that disagree resolve to nothing, which fails closed.
    """

    path: str
    lets: dict[str, str]
    file_consts: dict[str, str]
    tree_consts: dict[str, list[tuple[str, str]]]
    imports: dict[str, str]


USE_ONE = re.compile(r"\buse\s+((?:\w+::)+)(\w+)\s*;")
USE_GROUP = re.compile(r"\buse\s+((?:\w+::)+)\{([^{}]*)\}\s*;")
PATH_WORDS = {"crate", "self", "super"}


def imports_of(code: str) -> dict[str, str]:
    """Names a file imports by an explicit `use`, mapped to their module path."""
    found = {}
    for m in USE_ONE.finditer(code):
        found[m.group(2)] = m.group(1).rstrip(":")
    for m in USE_GROUP.finditer(code):
        for item in m.group(2).split(","):
            if re.fullmatch(r"\s*\w+\s*", item):
                found[item.strip()] = m.group(1).rstrip(":")
    return found


def module_parts(path: str) -> list[str]:
    """The module path a file holds, from its location: `a/mod.rs` and a crate
    root `src/lib.rs` / `src/main.rs` name their directory."""
    parts = path.removesuffix(".rs").split("/")
    if parts[-1] == "mod" or (len(parts) == 2 and parts[-1] in ("lib", "main")):
        return parts[:-1]
    return parts


def ancestors(path: str) -> list[list[str]]:
    """Modules whose items `use super::*` can reach from `path`, nearest first.

    A `x_tests.rs` file is attached under `x` by `#[path]`, so `x` counts too.
    """
    here = module_parts(path)
    found = [here[:n] for n in range(len(here) - 1, 0, -1)]
    if here[-1].endswith("_tests"):
        found.insert(0, here[:-1] + [here[-1].removesuffix("_tests")])
    return found


def candidates(name: str, qualifier: str, scope: Scope) -> list[tuple[str, str]]:
    """The definitions of `name` that the reference can mean."""
    entries = scope.tree_consts.get(name, [])
    module = [w for w in qualifier.split("::") if w and w not in PATH_WORDS]
    if module:
        return [(p, e) for p, e in entries if module_parts(p)[-len(module) :] == module]
    # A bare name, or only `super::` / `crate::` words: an ancestor's.
    for level in ancestors(scope.path):
        hits = [(p, e) for p, e in entries if module_parts(p) == level]
        if hits:
            return hits
    return []


def wrapped(expr: str) -> bool:
    """True when one pair of parentheses encloses all of `expr`."""
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth = 0
    for i, c in enumerate(expr):
        depth += {"(": 1, ")": -1}.get(c, 0)
        if depth == 0:
            return i == len(expr) - 1
    return False


def resolve(expr: str, scope: Scope, depth: int = 0) -> tuple[float, bool] | None:
    """(value, is_duration) of `expr` in seconds, or None when it does not resolve."""
    expr = expr.strip()
    while wrapped(expr):
        expr = expr[1:-1].strip()
    if depth > 4 or not expr:
        return None
    for seps in (("+", "-"), ("*", "/")):
        parts = split_top(expr, seps)
        if len(parts) > 1:
            values = [resolve(p, scope, depth + 1) for _, p in parts]
            if None in values:
                return None
            total, is_dur = values[0]
            for (sep, _), (v, d) in zip(parts[1:], values[1:]):
                if sep == "/" and v == 0:
                    return None
                total = {"+": total + v, "-": total - v, "*": total * v, "/": total / max(v, 1e-12)}[sep]
                is_dur = is_dur or d
            return total, is_dur
    if NUMBER.match(expr):
        return float(re.sub(r"_?(?:u|i|f)\d+$|usize$", "", expr).replace("_", "")), False
    if m := DURATION.fullmatch(expr):
        return float(m.group(2).replace("_", "")) * UNITS[m.group(1)], True
    if m := DURATION_F.match(expr):
        return float(m.group(1).replace("_", "")), True
    if re.fullmatch(r"(?:std::time::|tokio::time::)?Duration::ZERO", expr):
        return 0.0, True
    if re.fullmatch(r"(?:std::time::|tokio::time::)?Duration::MAX", expr):
        return float("inf"), True
    if re.fullmatch(r"\w+", expr) and expr in scope.lets:
        return resolve(scope.lets[expr], scope, depth + 1)
    if re.fullmatch(r"(?:\w+::)*[A-Z][A-Z0-9_]*", expr):
        qualifier, _, name = expr.rpartition("::")
        if not qualifier and name in scope.file_consts:
            return resolve(scope.file_consts[name], scope, depth + 1)
        if not qualifier:
            qualifier = scope.imports.get(name, "")
        found = candidates(name, qualifier, scope)
        if len({e for _, e in found}) != 1 or len({p for p, _ in found}) != 1:
            return None
        defining = found[0][0]
        own = {n: e for n, es in scope.tree_consts.items() for p, e in es if p == defining}
        return resolve(found[0][1], Scope(defining, {}, own, scope.tree_consts, {}), depth + 1)
    return None


LET = re.compile(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=\s*([^;]+);")
NOW = r"(?:(?:std|tokio)::time::)?Instant::now\(\)"
# `duration_since(UNIX_EPOCH)` is a timestamp, not a measured span.
MEASURED = re.compile(rf"\.elapsed\(\)|\bduration_since\((?!\s*(?:std::time::)?(?:SystemTime::)?UNIX_EPOCH)|{NOW}\s*-\s*\w")
DEADLINE = re.compile(rf"^{NOW}\s*\+\s*(.+)$", re.S)
NUMBER_UNIT = {"as_millis": 1e-3, "as_micros": 1e-6, "as_nanos": 1e-9}
UPPER = {"<": "left", "<=": "left", ">": "right", ">=": "right"}


def measured(expr: str, names: dict[str, float]) -> bool:
    return bool(MEASURED.search(expr)) or any(re.search(rf"\b{re.escape(n)}\b", expr) for n in names)


def unit_of(measured_side: str, names: dict[str, float]) -> float:
    """Seconds per unit when the measured side is a bare count (`as_millis()`)."""
    side = measured_side.strip()
    if m := re.search(r"\.(as_\w+)\(\)\s*$", side):
        return NUMBER_UNIT.get(m.group(1), 1.0)
    return names.get(side, 1.0)


def bindings(body: str) -> tuple[dict[str, str], dict[str, float], dict[str, str]]:
    """Fn-local lets, measured names with their unit, and deadline windows."""
    lets, names, deadlines = {}, {}, {}
    for m in LET.finditer(body):
        name, expr = m.group(1), m.group(2).strip()
        lets[name] = expr
        names.pop(name, None)
        deadlines.pop(name, None)
        if d := DEADLINE.match(expr):
            deadlines[name] = d.group(1)
        # A measured name passes on only through a plain alias or unit read: taint
        # carried through any expression marks a token built from a timestamp.
        elif MEASURED.search(expr) or re.fullmatch(r"(\w+)(?:\.as_\w+\(\))?", expr) and expr.split(".")[0] in names:
            names[name] = unit_of(expr, names)
    return lets, names, deadlines


def window_of(equality: bool, args: str, names: dict[str, float], deadlines: dict[str, str]):
    """(window expression, measured side) when `args` bounds a measured time from above."""
    if equality:
        parts = [p for _, p in split_top(args, (",",))][:2]
        if len(parts) == 2 and measured(parts[0], names) != measured(parts[1], names):
            return (parts[1], parts[0]) if measured(parts[0], names) else (parts[0], parts[1])
        return None
    cond = split_top(args, (",",))[0][1]
    for _, clause in split_top(cond, ("&&", "||")):
        sides = split_top(clause, ("<=", ">=", "<", ">"))
        if len(sides) != 2:
            continue
        (_, lhs), (op, rhs) = sides
        lhs, rhs = lhs.strip(), rhs.strip()
        bounded, window = (lhs, rhs) if UPPER[op] == "left" else (rhs, lhs)
        if measured(bounded, names) and not measured(window, names):
            return window, bounded
        if re.fullmatch(NOW, bounded) and window in deadlines:
            return deadlines[window], ""
        # The clock kept below something that is not a traced deadline
        # (`retry + 1 s >= Instant::now() + RETRY`, a deadline parameter): the
        # window is whatever slack that side holds, read as unresolvable.
        if re.search(NOW, bounded) and not re.search(NOW, window):
            return window, ""
    return None


def scan_text(path: str, text: str, tree_consts: dict[str, list[tuple[str, str]]]) -> list[Finding]:
    """Every assert in `text` that bounds a measured time under 5 s, or by a window that does not resolve."""
    code = blank_strings_and_comments(text)
    file_consts = {m.group(2): m.group(3) for m in CONST.finditer(code)}
    imports = imports_of(code)
    found = []
    fns = [(m.start(), m.group(1)) for m in FN.finditer(code)]
    for offset, equality, args in calls(code):
        at = bisect.bisect_left(fns, (offset,)) - 1
        start, fn = fns[at] if at >= 0 else (0, "<file>")
        lets, names, deadlines = bindings(code[start:offset])
        hit = window_of(equality, args, names, deadlines)
        if hit is None:
            continue
        expr, side = hit
        value = resolve(expr, Scope(path, lets, file_consts, tree_consts, imports))
        if value is not None:
            seconds = value[0] if value[1] else value[0] * unit_of(side, names)
            if seconds >= THRESHOLD_S:
                continue
        found.append(
            Finding(
                path,
                fn,
                normalise(code, offset),
                code.count("\n", 0, offset) + 1,
                None if value is None else seconds,
                "unresolvable window" if value is None else "under 5 s",
            )
        )
    return found


def normalise(code: str, offset: int) -> str:
    """The assert call at `offset`, strings blanked and whitespace collapsed."""
    depth, i = 0, code.index("(", offset)
    while i < len(code):
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
        if depth == 0:
            break
    return " ".join(code[offset:i].split())


def format_row(row: Row) -> str:
    return "\t".join(row)


def parse_allowlist(text: str) -> list[Row]:
    rows = []
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            path, fn, assertion, reason = line.split("\t")
            rows.append(Row(path, fn, assertion, reason))
    return rows


def judge(found: list[Finding], rows: list[Row], base: list[Row] | None) -> list[str]:
    """Errors: unlisted findings, stale or ambiguous rows, and rows not in `base`.

    `base` is the list at the base ref, or None when the base has none (the
    cutover), which is the one case the shrink-only comparison is skipped.
    """
    errors = []
    listed = set()
    for row in rows:
        matches = [f for f in found if (f.path, f.fn, f.assertion) == row[:3]]
        if not matches:
            errors.append(f"STALE {row.path} ({row.fn}): no such assert, drop the row: {row.assertion}")
        elif len(matches) > 1:
            lines = ", ".join(str(f.line) for f in matches)
            errors.append(f"AMBIGUOUS {row.path} ({row.fn}): the row matches lines {lines}: {row.assertion}")
        listed.update((f.path, f.line) for f in matches)
    errors += [str(f) for f in found if (f.path, f.line) not in listed]
    if base is not None:
        known = {r[:3] for r in base}
        errors += [
            f"NEW ROW {r.path} ({r.fn}): the allowlist is shrink-only; wait on an event instead: {r.assertion}"
            for r in rows
            if r[:3] not in known
        ]
    return errors


def rust_files():
    for top in SCANNED:
        yield from sorted((ROOT / top).rglob("*.rs"))


def tree_consts(texts: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """Every const by name, with the file defining it."""
    consts: dict[str, list[tuple[str, str]]] = {}
    for path, text in texts.items():
        for m in CONST.finditer(blank_strings_and_comments(text)):
            consts.setdefault(m.group(2), []).append((path, " ".join(m.group(3).split())))
    return consts


def read_base(ref: str) -> list[Row] | None:
    rel = ALLOWLIST.resolve().relative_to(ROOT.resolve()).as_posix()
    shown = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=ROOT, capture_output=True, text=True)
    if shown.returncode == 0:
        return parse_allowlist(shown.stdout)
    exists = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=ROOT, capture_output=True)
    if exists.returncode != 0:
        raise SystemExit(f"FAIL cannot read base {ref!r}; the shrink-only check is not skipped")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", metavar="REF", help="refuse allowlist rows added since REF")
    args = parser.parse_args(argv)
    texts = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8", errors="replace") for p in rust_files()}
    consts = tree_consts(texts)
    found = [f for path, text in texts.items() for f in scan_text(path, text, consts)]
    rows = parse_allowlist(ALLOWLIST.read_text(encoding="utf-8")) if ALLOWLIST.exists() else []
    errors = judge(found, rows, read_base(args.base) if args.base else None)
    for line in errors:
        print(line)
    print(f"{len(found)} timing asserts under {THRESHOLD_S:g} s or unresolvable, {len(rows)} allowlisted.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
