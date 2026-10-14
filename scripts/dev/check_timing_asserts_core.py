#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure leaf for the timing-assert guard: legacy lexer, resolution, 5 s scanners."""

from __future__ import annotations

import bisect
import functools
import re
from pathlib import PurePosixPath
from typing import NamedTuple

THRESHOLD_S = 5.0
HANG_BOUND_HOME = "src/gateway/mod.rs"

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
        if name == "HANG_BOUND" and not found:
            # One definition, reached through re-exports the module walk cannot
            # follow (`test_wait`, `gateway::test_helpers`): read it from source.
            found = [(p, e) for p, e in scope.tree_consts.get(name, []) if p == HANG_BOUND_HOME]
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


def scan_text(
    path: str, text: str, tree_consts: dict[str, list[tuple[str, str]]], threshold: float = THRESHOLD_S
) -> list[Finding]:
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
        end = fns[at + 1][0] if at + 1 < len(fns) else len(code)
        if paused_clock(code, start, end) and tokio_measured(side, lets, code):
            continue
        value = resolve(expr, Scope(path, lets, file_consts, tree_consts, imports))
        if value is not None:
            seconds = value[0] if value[1] else value[0] * unit_of(side, names)
            if seconds >= threshold:
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


TIMEOUT = re.compile(r"(?<![\w.])(?:(?:tokio::)?time::)?timeout\(")
# A test file, or a helper under a test module directory (`wire_tests/fixture.rs`).
TEST_FILE = re.compile(r"(^tests/|/tests/|_tests/|_tests\.rs$|/tests\.rs$)")
# A timeout's Result consumed so that expiry fails the test, read from the
# text right after `.await` (rustfmt may wrap each link onto its own line).
# What turns an expired timeout into a failed test, whether it follows the
# `.await` directly or a `let` binding of the result.
CONSUMED = r"(?:\.\s*(?:expect|unwrap)\s*\(|\?|\.\s*unwrap_or_else\(\s*\|[^|]*\|\s*panic!)"
FAILS_ON_EXPIRY = re.compile(r"\s*\.await\s*" + CONSUMED)
LET_BOUND = re.compile(r"let\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=\s*$")


def test_start(path: str, code: str) -> int | None:
    """Where test code starts in `code`: all of a test file, or from a product
    file's first `#[cfg(test)]` on (its inline test module). None: no tests."""
    if TEST_FILE.search(path):
        return 0
    m = re.search(r"#\[cfg\(test\)\]", code)
    return m.start() if m else None


def scan_timeouts(
    path: str,
    text: str,
    tree_consts: dict[str, list[tuple[str, str]]],
    includers: dict[str, str],
    threshold: float = THRESHOLD_S,
) -> list[Finding]:
    """Every `timeout(W, f)` in test code whose expiry fails the test, when W is
    under 5 s or does not resolve (MIK-8247).

    Fails the test: the Result is consumed by `.expect`, `.unwrap`, `?` or
    `.unwrap_or_else(|_| panic!(..))`, straight after `.await` or through a
    `let` binding the function later consumes the same way. A timeout whose
    Result is only inspected (`assert!(r.is_err())`, a cancellation) is not
    judged: it expects the window to pass.
    """
    code = blank_strings_and_comments(text)
    start = test_start(path, code)
    if start is None:
        return []
    file_consts = {m.group(2): m.group(3) for m in CONST.finditer(code)}
    # A file textually `include!`d into another shares that file's items.
    if path in includers:
        for name, entries in tree_consts.items():
            for where, expr in entries:
                if where == includers[path]:
                    file_consts.setdefault(name, expr)
    imports = imports_of(code)
    fns = [(m.start(), m.group(1)) for m in FN.finditer(code)]
    found = []
    for m in TIMEOUT.finditer(code, start):
        depth, end = 1, m.end()
        while end < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[end], 0)
            end += 1
        tail = code[end : end + 300]
        fails = bool(FAILS_ON_EXPIRY.match(tail))
        if not fails and re.match(r"\s*\.await\s*;", tail):
            bound = LET_BOUND.search(code[max(0, m.start() - 120) : m.start()])
            if bound:
                name = re.escape(bound.group(1))
                after = code[end : end + 2000]
                fails = bool(re.search(rf"\b{name}\s*{CONSUMED}", after))
        if not fails:
            continue
        at = bisect.bisect_left(fns, (m.start(),)) - 1
        fn_start, fn = fns[at] if at >= 0 else (0, "<file>")
        if paused_clock(code, fn_start, fns[at + 1][0] if at + 1 < len(fns) else len(code)):
            continue
        lets, _, _ = bindings(code[fn_start : m.start()])
        window = split_top(code[m.end() : end - 1], (",",))[0][1].strip()
        value = resolve(window, Scope(path, lets, file_consts, tree_consts, imports))
        seconds = None if value is None else value[0]
        if seconds is not None and seconds >= threshold:
            continue
        found.append(
            Finding(
                path,
                fn,
                " ".join(code[m.start() : end].split()),
                code.count("\n", 0, m.start()) + 1,
                seconds,
                "unresolvable window" if seconds is None else "under 5 s",
            )
        )
    return found


TOKIO_INSTANT_IMPORT = re.compile(r"use\s+tokio::time::(?:Instant\b|\{[^}]*\bInstant\b)")
STD_INSTANT_IMPORT = re.compile(r"use\s+std::time::(?:Instant\b|\{[^}]*\bInstant\b)")


def tokio_measured(side: str, lets: dict[str, str], code: str) -> bool:
    """Whether the time `side` measures was read from tokio's clock: its root
    `let` is `tokio::time::Instant::now()`, or a bare `Instant::now()` in a
    file that imports tokio's `Instant` and no std one (an import in any
    scope counts, so an ambiguous bare name is never exempted). Only that
    clock is virtual when paused; a `std::time::Instant` keeps reading real
    time, so an assert on it is judged on a paused clock too. An aliased
    import (`use tokio::time::Instant as T`) is not followed: the assert is
    judged, which refuses a valid row rather than passing a racing one."""
    seen: set[str] = set()
    expr = side
    while True:
        if "Instant::now()" in expr:
            return "tokio::time::Instant::now()" in expr or bool(
                re.search(r"(?<![\w:])Instant::now\(\)", expr)
                and TOKIO_INSTANT_IMPORT.search(code)
                and not STD_INSTANT_IMPORT.search(code)
            )
        root = re.match(r"\s*(\w+)", expr)
        if not root or root.group(1) not in lets or root.group(1) in seen:
            return False
        seen.add(root.group(1))
        expr = lets[root.group(1)]


def paused_clock(code: str, fn_start: int, fn_end: int) -> bool:
    """Whether the function at `fn_start` runs on tokio's paused clock: its
    attributes say `start_paused = true`, or its body calls `time::pause()`.
    There a timeout is virtual time, which load cannot make fire early, so it
    is not the wall-clock window this guard is about."""
    attrs = code[max(0, fn_start - 300) : fn_start]
    head = attrs[attrs.rfind("}") + 1 :] if "}" in attrs else attrs
    return "start_paused = true" in head or bool(re.search(r"\btime::pause\(\)", code[fn_start:fn_end]))


def block_end(code: str, open_at: int) -> int:
    """Offset just past the `}` matching the `{` at `open_at`."""
    depth, i = 0, open_at
    while i < len(code):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        i += 1
        if depth == 0:
            break
    return i


def call_args(code: str, open_paren: int) -> tuple[str, int]:
    """(text inside the parentheses opening at `open_paren`, offset past `)`)."""
    depth, i = 1, open_paren + 1
    while i < len(code) and depth:
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
    return code[open_paren + 1 : i - 1], i


def includers_of(texts: dict[str, str]) -> dict[str, str]:
    """Files pulled into another by `include!("rel")`, mapped to the includer."""
    found = {}
    for path, text in texts.items():
        for rel in re.findall(r'include!\(\s*"([^"]+\.rs)"\s*\)', text):
            target = (PurePosixPath(path).parent / rel).as_posix()
            parts = []
            for part in target.split("/"):
                if part == "..":
                    parts and parts.pop()
                elif part != ".":
                    parts.append(part)
            found["/".join(parts)] = path
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


def tree_consts(texts: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """Every const by name, with the file defining it."""
    consts: dict[str, list[tuple[str, str]]] = {}
    for path, text in texts.items():
        for m in CONST.finditer(blank_strings_and_comments(text)):
            consts.setdefault(m.group(2), []).append((path, " ".join(m.group(3).split())))
    return consts
