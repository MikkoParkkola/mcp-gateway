#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure new-code rules for the timing-assert guard: the PR-C 10 s floor family."""

from __future__ import annotations

import functools
import re
from typing import NamedTuple

from check_timing_asserts_core import (
    CONST,
    DURATION,
    FN,
    LET_BOUND,
    NOW,
    NUMBER,
    TIMEOUT,
    Finding,
    Scope,
    bindings,
    blank_strings_and_comments,
    block_end,
    call_args,
    calls,
    imports_of,
    paused_clock,
    resolve,
    scan_text,
    scan_timeouts,
    split_top,
    test_start,
)

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
SETTER = "short timeout set through a timeout-named builder or call"
FIELD = "short timeout field"
IS_OK = "timeout whose result is asserted is_ok, under the 10 s floor"
# MIK-8360 R3a: `.with_x_timeout(D)` / `.set_x_timeout(D)`, and any other
# call named for a timeout given a literal Duration (not `timeout(` itself,
# which the floor already judges, nor `timeout_at`).
SETTER_CALL = re.compile(r"\.(?:with|set)_\w*timeout\w*\(")
NAMED_CALL = re.compile(r"(?<![\w.:])(?!timeout\(|timeout_at\()(\w*timeout\w*)\(")
# MIK-8360 R3b: a struct-literal field named for a timeout. Unit by suffix: a
# bare number counts only under `_secs`/`_ms`/`_millis`.
TIMEOUT_FIELD = re.compile(r"(?<![\w.])(timeout|\w+_timeout|timeout_\w+)\s*:\s*([^,}\n]+)")
FIELD_UNITS = {"_secs": 1.0, "_ms": 1e-3, "_millis": 1e-3}
REASONS = ("absence", "lower-bound", "first-poll", "fixture", "precondition")
HANG_BOUND = re.compile(r"(?:\w+::)*HANG_BOUND\b")
TAG_LINE = re.compile(r"//\s*timing:(.*)$")
ORACLE_LINE = re.compile(r"//\s*timing-oracle:(.*)$")
ORACLE_FORMAT = re.compile(r"^\s*vs\s+(.*\S)\s*\(MIK-\d+\)\s*$")
ORACLE_SUBJECT = re.compile(r"\d+(?:\.\d+)?\s*(?:s|ms|us|ns)\b|\b[A-Z][A-Z0-9_]{2,}\b")
SLEEP_CALL = re.compile(r"(?<![\w.])(?:(?:tokio|std)::(?:time|thread)::|time::|thread::)?sleep\(")


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


def scan_new(
    path: str,
    text: str,
    consts: dict[str, list[tuple[str, str]]],
    includers: dict[str, str],
    added: set[int],
    carried=frozenset(),
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
        if new and (f.path, f.fn, f.assertion) not in carried and not HANG_BOUND.search(f.assertion) and not oracle_ok(f.line, f.assertion):
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

        found += timeout_shapes(path, fn, code, (body_open, body_end), touches, seconds, exempt)
    return found


def timeout_shapes(path, fn, code, span, touches, seconds, exempt) -> list[Finding]:
    """MIK-8360: a short timeout reaching a product by name, with no sleep.

    R3a a timeout-named builder or call; R3b a timeout-named field; R1b a
    `timeout(W, ..)` whose result is asserted `is_ok`. A window that does not
    resolve passes R3a and R3b (a generic helper's parameter), and fails R1b
    (its expiry fails the test, as the floor reads a `.expect`).
    """
    body_open, body_end = span
    line_of = lambda at: code.count("\n", 0, at) + 1  # noqa: E731
    found: list[Finding] = []

    def short(expr: str, at: int) -> float | None:
        value = seconds(expr, at)
        return value if value is not None and value < FLOOR_S else None

    def changed(start: int, end: int, expr: str) -> bool:
        """Any line from `start` to `end` changed, or the line binding `expr`."""
        bound = def_line_in(code, expr, line_of)
        return touches(line_of(start), line_of(end)) or (bound is not None and touches(bound, bound))

    for m in SETTER_CALL.finditer(code, body_open, body_end):
        args, end = call_args(code, m.end() - 1)
        expr, line = split_top(args, (",",))[0][1].strip(), line_of(m.start())
        if (value := short(expr, m.start())) is not None and changed(m.start(), end, expr) and not exempt(line, expr):
            found.append(Finding(path, fn, f"{m.group(0)}{expr})", line, value, SETTER))
    for m in NAMED_CALL.finditer(code, body_open, body_end):
        args, end = call_args(code, m.end() - 1)
        line = line_of(m.start())
        for _, arg in split_top(args, (",",)):
            expr = arg.strip()
            if DURATION.fullmatch(expr) and (value := short(expr, m.start())) is not None:
                if changed(m.start(), end, expr) and not exempt(line, expr):
                    found.append(Finding(path, fn, f"{m.group(1)}(.., {expr})", line, value, SETTER))
                break
    for m in TIMEOUT_FIELD.finditer(code, body_open, body_end):
        name, expr, line = m.group(1), m.group(2).strip(), line_of(m.start())
        unit = next((u for suffix, u in FIELD_UNITS.items() if name.endswith(suffix)), None)
        if unit is not None and NUMBER.match(expr):
            value = float(re.sub(r"_?(?:[uif]\d+|usize|isize)$", "", expr).replace("_", "")) * unit
            value = value if value < FLOOR_S else None
        elif DURATION.search(expr) or "::" in expr or expr.isupper():
            value = short(expr, m.start())
        else:
            value = None
        if value is not None and changed(m.start(), m.end(), expr) and not exempt(line, expr):
            found.append(Finding(path, fn, f"{name}: {expr}", line, value, FIELD))
    for m in TIMEOUT.finditer(code, body_open, body_end):
        args, end = call_args(code, m.end() - 1)
        inline = re.match(r"\s*\.await\s*\.\s*is_ok\(\)", code[end : end + 40]) and re.search(
            r"(?:debug_)?assert!\s*\(\s*$", code[max(0, m.start() - 80) : m.start()]
        )
        bound = LET_BOUND.search(code[max(0, m.start() - 120) : m.start()])
        later = bound and re.match(r"\s*\.await\s*;", code[end : end + 40]) and re.search(
            rf"(?:debug_)?assert!\s*\(\s*{bound.group(1)}\s*\.\s*is_ok\(\)", code[end:body_end]
        )
        if not (inline or later):
            continue
        # The span runs from the call through the assert that consumes it.
        consumed = end + 40 if inline else end + later.end()
        expr, line = split_top(args, (",",))[0][1].strip(), line_of(m.start())
        value = seconds(expr, m.start())
        if (value is None or value < FLOOR_S) and changed(m.start(), consumed, expr) and not exempt(line, expr):
            found.append(Finding(path, fn, f"timeout({expr}, ..)", line, value, IS_OK))
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
