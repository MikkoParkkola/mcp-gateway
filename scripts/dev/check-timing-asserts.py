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

Timeouts get the same cutoff (MIK-8247). In test code, a `timeout(W, f)`
whose expiry fails the test (`.await` then `.expect`, `.unwrap`, `?` or
`.unwrap_or_else(|_| panic!..)`, directly or through a `let` binding) is
refused when W is under 5 s or cannot be resolved. A fn on a paused clock
(`start_paused = true`, `time::pause()`) is skipped: its time is virtual.
Test code is a test path, or a product file from its first `#[cfg(test)]`.
A const reaches a file `include!`d by the file that defines it.

Stated misses: a `sleep` used as a window; a timeout that is expected to
elapse and is then asserted on; a window passed in through a constructor or
helper; `timeout_at`; a `select!` arm on `sleep`; a `let`-bound result first
consumed over 2000 characters later; a fn that pauses the clock partway, which
is skipped whole; a commented-out `include!`, or a file included by two files
(the last includer's consts are used). A same-named binding that shadows the
timeout's result can be read as consuming it: that fails loudly, never quietly.

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
from pathlib import Path, PurePosixPath
from typing import NamedTuple

THRESHOLD_S = 5.0
ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path(__file__).with_name("timing-asserts-allowlist.tsv")
SCANNED = ("src", "tests", "crates")
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


def paused_clock(code: str, fn_start: int, fn_end: int) -> bool:
    """Whether the function at `fn_start` runs on tokio's paused clock: its
    attributes say `start_paused = true`, or its body calls `time::pause()`.
    There a timeout is virtual time, which load cannot make fire early, so it
    is not the wall-clock window this guard is about."""
    attrs = code[max(0, fn_start - 300) : fn_start]
    head = attrs[attrs.rfind("}") + 1 :] if "}" in attrs else attrs
    return "start_paused = true" in head or bool(re.search(r"\btime::pause\(\)", code[fn_start:fn_end]))


# PR-C (MIK-8247, MIK-8288): rules for new or changed code only, read against
# `--base`. Existing sites are judged by the 5 s rule above and by MIK-8266's
# triage, not here.
FLOOR_S = 10.0
FLOOR = "under the 10 s floor"
SLEEP = "sleep used as a window"
ELAPSE = "timeout expected to elapse, then asserted"
TAG = "unknown timing tag"
ORACLE = "malformed timing-oracle"
ABSENCE = "absence tag on a collector not named for absence"
BUDGET = "poll budget under 10 s"
TIMER = "short product timer slept against on the real clock"
REASONS = ("absence", "lower-bound", "first-poll", "fixture", "precondition")
HANG_BOUND = re.compile(r"(?:\w+::)*HANG_BOUND\b")
TAG_LINE = re.compile(r"//\s*timing:(.*)$")
ORACLE_LINE = re.compile(r"//\s*timing-oracle:(.*)$")
ORACLE_FORMAT = re.compile(r"^\s*vs\s+(.*\S)\s*\(MIK-\d+\)\s*$")
ORACLE_SUBJECT = re.compile(r"\d+(?:\.\d+)?\s*(?:s|ms|us|ns)\b|\b[A-Z][A-Z0-9_]{2,}\b")
SLEEP_CALL = re.compile(r"(?<![\w.])(?:(?:tokio|std)::(?:time|thread)::|time::|thread::)?sleep\(")


def added_lines(base: str) -> dict[str, set[int]]:
    """Lines added or changed since the merge base with `base`, by path.

    Read from the working tree, so uncommitted edits count as new.
    """
    merge_base = subprocess.run(
        ["git", "merge-base", base, "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip() or base
    diff = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", "--no-renames", merge_base, "--", *SCANNED],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found: dict[str, set[int]] = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@") and path:
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            first, count = int(m.group(1)), int(m.group(2) or 1)
            found.setdefault(path, set()).update(range(first, first + count))
    return {p: lines for p, lines in found.items() if lines}


def comment_on(lines: list[str], line: int, pattern: re.Pattern) -> re.Match | None:
    """`pattern` in a comment on 1-based `line` or the line above it."""
    for n in (line, line - 1):
        if 1 <= n <= len(lines) and (m := pattern.search(lines[n - 1])):
            return m
    return None


def binding_lines(code: str, expr: str) -> list[int]:
    """Lines binding each plain name in `expr`: a `let` or a `const` in `code`."""
    found = []
    for name in set(re.findall(r"\b[A-Za-z_]\w*\b", expr)):
        last = None
        for last in re.finditer(rf"\b(?:let\s+(?:mut\s+)?|const\s+){name}\b", code):
            pass
        if last:
            found.append(code.count("\n", 0, last.start()) + 1)
    return found


def oracle_covers(text: str, line: int, expr: str) -> bool:
    """A well-formed `timing-oracle:` at the window's line or at the binding of
    a name its window expression uses (C: "at its constant or call")."""
    raw, code = text.splitlines(), blank_strings_and_comments(text)
    for n in [line, *binding_lines(code, expr)]:
        if (m := comment_on(raw, n, ORACLE_LINE)) and not oracle_malformed(m):
            return True
    return False


def statement_end(code: str, line: int) -> int:
    """The line of the `;` that ends the statement starting on `line`."""
    at = 0
    for _ in range(line - 1):
        at = code.index("\n", at) + 1
    end = code.find(";", at)
    return code.count("\n", 0, end if end >= 0 else len(code)) + 1


def oracle_malformed(m: re.Match) -> bool:
    """True when a `timing-oracle:` comment does not name a timer and a ticket."""
    f = ORACLE_FORMAT.match(m.group(1))
    return not (f and ORACLE_SUBJECT.search(f.group(1)))


def block_end(code: str, open_at: int) -> int:
    """Offset just past the `}` matching the `{` at `open_at`."""
    depth, i = 0, open_at
    while i < len(code):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        i += 1
        if depth == 0:
            break
    return i


class Loop(NamedTuple):
    kind: str  # for | while | loop
    header: str
    body: tuple[int, int]
    end: int


LOOP = re.compile(r"\b(for|while|loop)\b([^{;]*)\{")
EXIT = re.compile(r"\b(?:break|return)\b")
FAILS_AFTER = re.compile(r"\s*(?:(?:debug_)?assert(?:_eq|_ne)?!|panic!|unreachable!|bail!|return\s+Err\b|Err\()")


def loops_in(code: str, start: int, end: int) -> list[Loop]:
    found = []
    for m in LOOP.finditer(code, start, end):
        open_at = m.end() - 1
        close = block_end(code, open_at)
        found.append(Loop(m.group(1), m.group(2), (open_at + 1, close - 1), close))
    return found


def innermost(loops: list[Loop], at: int) -> Loop | None:
    inside = [lp for lp in loops if lp.body[0] <= at < lp.body[1]]
    return max(inside, key=lambda lp: lp.body[0]) if inside else None


def deadline_assert(args: str) -> bool:
    """`assert!(Instant::now() < deadline, ..)`: a hang guard, not a check."""
    return bool(re.match(rf"\s*{NOW}\s*<", args))


def is_poll(code: str, loop: Loop) -> bool:
    """A loop that exits on a condition, with no assert before that exit (B).

    A `while` exits in its header. A `for` or `loop` exits at its first
    `break` or `return`; an assert before the `if` holding it makes the loop
    paced, unless it only checks a deadline (precedence, v3.1).
    """
    if loop.kind == "while":
        return True
    body = code[loop.body[0] : loop.body[1]]
    exit_at = EXIT.search(body)
    if exit_at is None:
        return False
    guard_at = body.rfind("if", 0, exit_at.start())
    before = body[: guard_at if guard_at >= 0 else exit_at.start()]
    return all(deadline_assert(args) for _, _, args in calls(before))


@functools.lru_cache(maxsize=64)
def fn_spans(code: str) -> list[tuple[int, str, int, int]]:
    """(attribute start, name, body start, body end) for each fn with a body."""
    spans = []
    for m in FN.finditer(code):
        brace = code.find("{", m.end())
        semi = code.find(";", m.end())
        if brace < 0 or 0 <= semi < brace:
            continue
        spans.append((m.start(), m.group(1), brace, block_end(code, brace)))
    return spans


def call_args(code: str, open_paren: int) -> tuple[str, int]:
    """(text inside the parentheses opening at `open_paren`, offset past `)`)."""
    depth, i = 1, open_paren + 1
    while i < len(code) and depth:
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
    return code[open_paren + 1 : i - 1], i


def scan_new(
    path: str,
    text: str,
    consts: dict[str, list[tuple[str, str]]],
    includers: dict[str, str],
    added: set[int],
) -> list[Finding]:
    """PR-C's rules on the spans of `text` that touch an `added` line."""
    code = blank_strings_and_comments(text)
    start = test_start(path, code)
    if start is None or not added:
        return []
    raw = text.splitlines()
    line_of = lambda at: code.count("\n", 0, at) + 1  # noqa: E731
    touches = lambda a, b: any(n in added for n in range(a, b + 1))  # noqa: E731
    file_consts = {m.group(2): m.group(3) for m in CONST.finditer(code)}
    if path in includers:
        for name, entries in consts.items():
            for where, expr in entries:
                if where == includers[path]:
                    file_consts.setdefault(name, expr)
    imports = imports_of(code)
    found: list[Finding] = []

    def flag(at: int, fn: str, what: str, seconds: float | None, rule: str) -> None:
        found.append(Finding(path, fn, " ".join(what.split()), line_of(at), seconds, rule))

    def oracle_ok(line: int, expr: str) -> bool:
        return oracle_covers(text, line, expr)

    def tag_ok(line: int) -> bool:
        m = comment_on(raw, line, TAG_LINE)
        return bool(m) and m.group(1).strip() in REASONS

    # Comments on new lines: the closed tag set, the oracle format, and the
    # absence tag's binding to an absence collector (v3.2).
    # A tag above a changed statement is judged too: the binding is the pair.
    for n in sorted(added | {n - 1 for n in added}):
        if not 1 <= n <= len(raw):
            continue
        if (m := TAG_LINE.search(raw[n - 1])) and line_of(start) <= n:
            token = m.group(1).strip()
            if token not in REASONS:
                if n in added:
                    found.append(Finding(path, "", raw[n - 1].strip(), n, None, TAG))
            elif token == "absence":
                stmt = code.splitlines()[n - 1] if code.splitlines()[n - 1].strip() else (code.splitlines()[n:n + 1] or [""])[0]
                if not (SLEEP_CALL.search(stmt) or TIMEOUT.search(stmt) or "_for_absence(" in stmt):
                    found.append(Finding(path, "", raw[n - 1].strip(), n, None, ABSENCE))
        if n in added and (m := ORACLE_LINE.search(raw[n - 1])) and oracle_malformed(m):
            found.append(Finding(path, "", raw[n - 1].strip(), n, None, ORACLE))

    # A. The floor on the windows the 5 s rule already reads.
    windows = scan_text(path, text, consts, FLOOR_S) + scan_timeouts(path, text, consts, includers, FLOOR_S)
    for f in windows:
        # New when any line of the statement changed, or the binding of a name
        # its window uses (#3746 review).
        span = range(f.line, statement_end(code, f.line) + 1)
        new = any(n in added for n in span) or any(n in added for n in binding_lines(code, f.assertion))
        if new and not HANG_BOUND.search(f.assertion) and not oracle_ok(f.line, f.assertion):
            found.append(f._replace(rule=FLOOR))
    return found + scan_new_shapes(path, code, raw, start, added, Scope(path, {}, file_consts, consts, imports), oracle_ok, tag_ok)


def scan_new_shapes(path, code, raw, start, added, scope, oracle_ok, tag_ok) -> list[Finding]:
    """v2's sleep and expected-elapse shapes, B's loops, G's poll budget, D's timer."""
    found: list[Finding] = []
    line_of = lambda at: code.count("\n", 0, at) + 1  # noqa: E731
    touches = lambda a, b: any(n in added for n in range(a, b + 1))  # noqa: E731
    for attr_at, fn, body_open, body_end in fn_spans(code):
        if body_end <= start or paused_clock(code, attr_at, body_end):
            continue
        fn_scope = scope._replace(lets=bindings(code[body_open:body_end])[0])

        def seen_at(at: int):
            """The scope at `at`: a later `let` cannot excuse an earlier call."""
            return scope._replace(lets=bindings(code[body_open:at])[0])
        loops = loops_in(code, body_open, body_end)
        asserts = [(at, args) for at, _, args in calls(code[:body_end]) if at > body_open]

        def seconds(expr: str, at: int) -> float | None:
            if HANG_BOUND.fullmatch(expr.strip()):
                return float("inf")
            value = resolve(expr, seen_at(at))
            return None if value is None else value[0]

        def exempt(line: int, expr: str) -> bool:
            return tag_ok(line) or oracle_ok(line, expr)

        sleeps = []
        for m in SLEEP_CALL.finditer(code, body_open, body_end):
            args, _ = call_args(code, m.end() - 1)
            if innermost_fn(code, m.start()) == attr_at:
                sleeps.append((m.start(), args.strip()))
        # D counts a sleep the test waits out, not a poll's interval: polling
        # until the product acts is the event wait D asks for.
        waited = [(at, e) for at, e in sleeps if not ((lp := innermost(loops, at)) and is_poll(code, lp))]

        for at, expr in sleeps:
            line, value = line_of(at), seconds(expr, at)
            loop = innermost(loops, at)
            if loop and is_poll(code, loop):
                # G. A count-bounded poll that fails after the loop.
                count = re.fullmatch(r"\s*\w+\s+in\s+0\s*\.\.(=?)\s*(.+?)\s*", loop.header) if loop.kind == "for" else None
                if count and FAILS_AFTER.match(code, loop.end) and touches(line_of(loop.body[0]), line_of(loop.end) + 1):
                    n = resolve(count.group(2), fn_scope)
                    budget = None if n is None or value is None else (n[0] + bool(count.group(1))) * value
                    if budget is None or budget < FLOOR_S:
                        found.append(Finding(path, fn, " ".join(f"{loop.kind} {loop.header}".split()), line, budget, BUDGET))
                continue
            if value is not None and value >= FLOOR_S:
                continue
            # v2 (i): an assert later in the fn, or anywhere in a paced loop's body.
            later = [a for a, _ in asserts if a > at or (loop and loop.body[0] <= a < loop.body[1])]
            if not later:
                continue
            last = line_of(max(later))
            span_new = touches(min(line, line_of(min(later))), last) or (def_line_in(code, expr, line_of) in added)
            if span_new and not exempt(line, expr):
                found.append(Finding(path, fn, f"sleep({expr})", line, value, SLEEP))

        # v2 (ii): `let x = timeout(W, ..).await;`, `x.is_err()` asserted, then another assert.
        for m in TIMEOUT.finditer(code, body_open, body_end):
            bound = LET_BOUND.search(code[max(0, m.start() - 120) : m.start()])
            args, end = call_args(code, m.end() - 1)
            if not bound or not re.match(r"\s*\.await\s*;", code[end : end + 40]):
                continue
            name = bound.group(1)
            errs = [a for a, args_ in asserts if a > m.start() and re.search(rf"\b{name}\s*\.\s*is_err\(\)", args_)]
            if not errs or not [a for a, _ in asserts if a > errs[0]]:
                continue
            expr = split_top(args, (",",))[0][1].strip()
            value, line = seconds(expr, m.start()), line_of(m.start())
            last = line_of(max(a for a, _ in asserts if a > errs[0]))
            if (value is None or value < FLOOR_S) and touches(line, last) and not exempt(line, expr):
                found.append(Finding(path, fn, f"timeout({expr}, ..)", line, value, ELAPSE))

        # D. A product timer under the floor plus a real-clock sleep.
        if waited:
            for m in re.finditer(r"\b\w+_(?:ttl|interval|timeout|period)\s*:\s*([^,}\n]+)", code[body_open:body_end]):
                at = body_open + m.start()
                value = seconds(m.group(1), at)
                if value is not None and value < FLOOR_S and touches(line_of(at), line_of(waited[-1][0])):
                    found.append(Finding(path, fn, m.group(0), line_of(at), value, TIMER))
                    break
    return found


def innermost_fn(code: str, at: int) -> int | None:
    inside = [a for a, _, o, e in fn_spans(code) if o < at < e]
    return max(inside) if inside else None


def def_line_in(code: str, expr: str, line_of) -> int | None:
    """The line binding `expr` when it is a plain name: a `let` or a `const`."""
    name = expr.strip()
    if not re.fullmatch(r"\w+", name):
        return None
    m = None
    for m in re.finditer(rf"\b(?:let\s+(?:mut\s+)?|const\s+){name}\b", code):
        pass
    return line_of(m.start()) if m else None


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


def judge_new(found, rows, texts, consts, includers, added):
    """(findings left for the 5 s rule, new-code errors), given added lines.

    A window on a changed line that carries a well-formed `timing-oracle:` is
    excused from the 5 s rule too (C), so an oracle under 5 s is possible. A
    new-code error is dropped only where the 5 s rule already reports the
    same line as an error; an allowlisted line in a changed span is still
    judged as new, so the allowlist never covers new code (#3746 review).
    """
    kept = [
        f
        for f in found
        if not (f.line in added.get(f.path, ()) and oracle_covers(texts[f.path], f.line, f.assertion))
    ]
    listed = {r[:3] for r in rows}
    reported = {(f.path, f.line) for f in kept if (f.path, f.fn, f.assertion) not in listed}
    errors = [
        str(f)
        for path, lines in sorted(added.items())
        if path in texts
        for f in scan_new(path, texts[path], consts, includers, lines)
        if (f.path, f.line) not in reported
    ]
    return kept, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", metavar="REF", help="refuse allowlist rows added since REF")
    args = parser.parse_args(argv)
    texts = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8", errors="replace") for p in rust_files()}
    consts = tree_consts(texts)
    includers = includers_of(texts)
    found = [f for path, text in texts.items() for f in scan_text(path, text, consts)]
    found += [f for path, text in texts.items() for f in scan_timeouts(path, text, consts, includers)]
    rows = parse_allowlist(ALLOWLIST.read_text(encoding="utf-8")) if ALLOWLIST.exists() else []
    new_errors: list[str] = []
    if args.base:
        # PR-C: new or changed spans only (judge_new).
        found, new_errors = judge_new(found, rows, texts, consts, includers, added_lines(args.base))
    else:
        print("No --base: the new-code rules (10 s floor, sleep windows, poll budgets) were not run.")
    errors = judge(found, rows, read_base(args.base) if args.base else None) + new_errors
    for line in errors:
        print(line)
    print(f"{len(found)} timing asserts or timeouts under {THRESHOLD_S:g} s or unresolvable, {len(rows)} allowlisted.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
