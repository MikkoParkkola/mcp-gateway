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
    candidates,
    imports_of,
    paused_clock,
    resolve,
    scan_text,
    scan_timeouts,
    split_top,
    test_lines,
    tree_consts,
)
from check_timing_asserts_source import _signature_body

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
# Label that starts every finding of the product-timer rule (#3826): a test
# bound derived from a timer the product itself runs, so a slow host that
# uses the timer up also fails the test.
PRODUCT_BUDGET = "product budget:"
ADVICE = "wait for the event itself; a hang guard sits far above any product timer the work may use"
ONE_DURATION = re.compile(r"(?:std::time::|tokio::time::)?Duration::from_(?:secs|millis)\(\s*[\d_]+\s*\)")
WITHIN = re.compile(r"\b(\w+_within)\s*\(")
NEVER_A_NAME = frozenset("mut ref move async await let as self Self crate super true false in".split())


class Budgets(NamedTuple):
    """Product timers. `consts`: name -> (path, line, seconds) of each
    `const NAME: Duration` written as one from_secs/from_millis outside test
    code (HANG_BOUND excluded). `within`: names of product fns ending `_within`."""

    consts: dict[str, list[tuple[str, int, float]]]
    within: frozenset[str]


def budgets_of(texts: dict[str, str], consts=None) -> Budgets:
    """`consts`: the tree's consts when the caller has read them already."""
    timers: dict[str, list[tuple[str, int, float]]] = {}
    for name, defs in (consts if consts is not None else tree_consts(texts)).items():
        if name == "HANG_BOUND":
            continue
        for where in sorted({p for p, _ in defs}):
            # Every definition of the name in this file must be the same one
            # duration, as `resolve` would accept it; else it names nothing.
            forms = {expr for p, expr in defs if p == where}
            if len(forms) != 1 or not ONE_DURATION.fullmatch(form := forms.pop()):
                continue
            seconds = resolve(form, Scope(where, {}, {}, {}, {}))[0]
            code, tested = blank_strings_and_comments(texts[where]), test_lines(where, texts[where])
            for spot in re.finditer(rf"\bconst\s+{name}\s*:", code):
                if (line := code.count("\n", 0, spot.start()) + 1) not in tested:
                    timers.setdefault(name, []).append((where, line, seconds))
    product_fns = set()
    for path, text in texts.items():
        if "_within" not in text:
            continue
        code = blank_strings_and_comments(text)
        named = [m for m in FN.finditer(code) if m.group(1).endswith("_within")]
        if named:
            tested = test_lines(path, text)
            product_fns |= {m.group(1) for m in named if code.count("\n", 0, m.start()) + 1 not in tested}
    return Budgets(timers, frozenset(product_fns))


@functools.lru_cache(maxsize=64)
def _brace_pairs(code: str) -> tuple[tuple[int, int], ...]:
    """(open, close) offsets of every matched brace pair in `code`."""
    pairs, open_stack = [], []
    for brace in re.finditer(r"[{}]", code):
        if brace.group() == "{":
            open_stack.append(brace.start())
        elif open_stack:
            pairs.append((open_stack.pop(), brace.start()))
    return tuple(sorted(pairs))


def _scopes_around(code: str, at: int) -> list[tuple[int, int]]:
    """The brace pairs holding `at`, nearest first, then the whole file."""
    holding = [pair for pair in _brace_pairs(code) if pair[0] < at < pair[1]]
    return sorted(holding, reverse=True) + [(-1, len(code))]


def _home(code: str, pos: int) -> int:
    """The `{` of the nearest brace pair holding `pos`; -1 at file level."""
    return _scopes_around(code, pos)[0][0]


def statement_close(code: str, start: int) -> int:
    """Offset where the statement at `start` ends: the first `;` outside any
    brackets it opens, or the `}` of its own block if that comes first."""
    i = start
    while i < len(code):
        if code[i] == "(":
            i = call_args(code, i)[1]
        elif code[i] == "{":
            i = block_end(code, i)
        elif code[i] in ";}":
            return i
        else:
            i += 1
    return len(code)


def visible_binding(code: str, name: str, at: int) -> int | None:
    """Offset of the `let` or `const` that `name` refers to at `at`, or None.

    Scopes are tried from the nearest outward, the file last. In a scope, a
    const item sitting right in it wins wherever it is placed; failing that,
    the latest let sitting right in it whose `;` is behind `at`. Rust starts a
    let's scope after its statement, so `let a = a * 2` reads the earlier
    `a`. Pattern, parameter and macro bindings are not seen: accepted miss.
    """
    if name in NEVER_A_NAME:
        return None
    lets = re.compile(rf"\blet\s+(?:mut\s+)?{re.escape(name)}\b")
    items = re.compile(rf"\bconst\s+{re.escape(name)}\s*:")
    for opening, closing in _scopes_around(code, at):
        here = [m.start() for m in items.finditer(code, opening + 1, closing) if _home(code, m.start()) == opening]
        if here:
            return here[0]
        earlier = [
            m.start()
            for m in lets.finditer(code, opening + 1, at)
            if _home(code, m.start()) == opening and statement_close(code, m.start()) < at
        ]
        if earlier:
            return earlier[-1]
    return None


def right_side(code: str, binding: int) -> tuple[str, int] | None:
    """(text, offset) of what the let or const at `binding` is set to."""
    head = re.compile(r"(?:let\s+(?:mut\s+)?\w+|const\s+\w+)\s*(?::[^=;]+)?=\s*").match(code, binding)
    return None if head is None else (code[head.end() : statement_close(code, binding)], head.end())


class Named(NamedTuple):
    name: str
    path: str
    line: int
    seconds: float


def _timer(budgets: Budgets, name: str, path: str, line: int | None = None) -> Named | None:
    return next((Named(name, p, n, s) for p, n, s in budgets.consts.get(name, []) if p == path and line in (None, n)), None)


def named_budgets(expr: str, at: int, code: str, scope: Scope, budgets: Budgets, depth: int = 0):
    """(timers `expr` is derived from, lines of the local bindings it went
    through). A name bound locally is followed into its right-hand side, read
    from where that is written, unless it is a product const of this file;
    `resolve`'s depth limit applies. A path (`super::X`) is looked up only
    through modules. HANG_BOUND is never a timer."""
    timers: list[Named] = []
    passed: set[int] = set()
    if depth > 4:
        return timers, passed
    for token in re.finditer(r"(?<![\w.:])((?:\w+::)*)([A-Za-z_]\w*)\b(?!\s*[(!:])", expr):
        path_part, name = token.group(1).rstrip(":"), token.group(2)
        if name in NEVER_A_NAME or name == "HANG_BOUND":
            continue
        if not path_part:
            local = visible_binding(code, name, at)
            if local is not None:
                line = code.count("\n", 0, local) + 1
                passed.add(line)
                if own := _timer(budgets, name, scope.path, line):
                    timers.append(own)
                elif rhs := right_side(code, local):
                    deeper, through = named_budgets(rhs[0], rhs[1], code, scope, budgets, depth + 1)
                    timers += deeper
                    passed |= through
                continue
            path_part = scope.imports.get(name, "")
        if name[:1].isupper():
            defs = candidates(name, path_part, scope)
            if len({p for p, _ in defs}) == 1 and (other := _timer(budgets, name, defs[0][0])):
                timers.append(other)
    return timers, passed


CARRIED_CALL = re.compile(r"(?:(?:\w+::)*\w+\s*\.\s*)*(?:\w+::)*(\w+_within)\s*\(")


def carriers(code: str, start: int, end: int, budgets: Budgets, own_future: bool = True):
    """([(fn, argument text, offset of its `(`)], lines) for the product
    `*_within` calls that awaiting the future `code[start:end]` runs: the call
    itself (any path or receiver before it), the calls in the body of an
    `async` block, or those of a spawn whose argument is one of these two.
    Only the timeout's own future may be a plain name; its visible let is
    read, and that let's lines are returned so an edit inside it counts as
    new. A bare `{ .. }` block runs before any future is built: never a carrier."""
    lead = re.compile(r"\s*(?:&\s*(?:mut\s+)?)?").match(code, start, end).end()
    tail = end - (len(code[lead:end]) - len(code[lead:end].rstrip()))
    if call := CARRIED_CALL.match(code, lead, tail):
        args, past = call_args(code, call.end() - 1)
        whole = past >= tail and call.group(1) in budgets.within
        return ([(call.group(1), args, call.end() - 1)] if whole else []), set()
    if block := re.compile(r"async\s+(?:move\s+)?\{").match(code, lead, tail):
        close = block_end(code, block.end() - 1)
        inside = [c for c in WITHIN.finditer(code, block.end(), close) if c.group(1) in budgets.within]
        return [(c.group(1), call_args(code, c.end() - 1)[0], c.end() - 1) for c in inside], set()
    if spawn := re.compile(r"(?:\w+::)*spawn\s*\(").match(code, lead, tail):
        past = call_args(code, spawn.end() - 1)[1]
        return carriers(code, spawn.end(), past - 1, budgets, own_future=False)[0], set()
    name = re.compile(r"\w+").fullmatch(code, lead, tail)
    if own_future and name and (local := visible_binding(code, name.group(), start)) is not None:
        if rhs := right_side(code, local):
            calls, _ = carriers(code, rhs[1], rhs[1] + len(rhs[0]), budgets, own_future=False)
            first, last = code.count("\n", 0, local) + 1, code.count("\n", 0, rhs[1] + len(rhs[0])) + 1
            return calls, set(range(first, last + 1))
    return [], set()


def line_offset(code: str, line: int) -> int:
    """Offset of the first non-blank character of 1-based `line`."""
    begin = sum(len(row) + 1 for row in code.split("\n")[: line - 1])
    return begin + len(code[begin:]) - len(code[begin:].lstrip(" \t"))


def _written_at(code: str, at: int, window: str) -> int:
    """Where to read an assert's window: at the `Instant::now() + W` of the
    deadline let it compares against, when it comes from one; else the assert."""
    # Only the condition, and only the name it holds against the clock: a
    # message argument naming some other deadline must not move the reading.
    condition = split_top(call_args(code, code.index("(", at))[0], (",",))[0][1]
    compared = re.search(rf"{NOW}\s*<=?\s*(\w+)\b|\b(\w+)\s*>=?\s*{NOW}", condition)
    name = compared and (compared.group(1) or compared.group(2))
    local = visible_binding(code, name, at) if name else None
    rhs = right_side(code, local) if local is not None else None
    plus = re.match(rf"\s*{NOW}\s*\+\s*", rhs[0]) if rhs else None
    if plus and rhs[0][plus.end() :].strip() == window:
        return rhs[1] + plus.end()
    return at


@functools.lru_cache(maxsize=64)
def _file_level(code: str) -> tuple[dict[str, str], dict[str, str]]:
    """(the file's own consts, its `use` imports), read once per file."""
    return dict((c[2], c[3]) for c in CONST.finditer(code)), imports_of(code)


def _scope_at(path: str, code: str, at: int, consts) -> Scope:
    body = next((s for _, _, s, e in fn_spans(code) if s < at < e), 0)
    own, imported = _file_level(code)
    return Scope(path, bindings(code[body:at])[0], own, consts, imported)


def _argument_value(path: str, code: str, arg: str, paren: int, consts):
    """`resolve` of one call argument, a bare name read through the binding
    visible at the call (so a let inside an enclosing block is seen)."""
    if re.fullmatch(r"\w+", arg) and (local := visible_binding(code, arg, paren)) is not None:
        if (rhs := right_side(code, local)) is not None:
            return resolve(rhs[0], _scope_at(path, code, rhs[1], consts))
    return resolve(arg, _scope_at(path, code, paren, consts))


def budget_sites(path: str, text: str, consts, includers, budgets: Budgets):
    """(finding, offset, rule, chain lines, list text) per test-code window a
    product timer decides. Refused in new code (rule set): a window derived
    from a named timer, or at most an explicit budget that the timed future
    itself passes to `*_within`. Listed only (rule ""): a literal under the
    floor equal to a timer the file can reach."""
    code, tested = blank_strings_and_comments(text), test_lines(path, text)
    sites: list = []
    scan_timeouts(path, text, consts, includers, float("inf"), sites=sites)
    asserts: list = []
    scan_text(path, text, consts, float("inf"), sites=asserts)
    windows = []
    for f, at, args in sites:
        opened = TIMEOUT.match(code, at).end()
        parts = split_top(args, (",",))
        future = (opened + len(parts[0][1]) + 1, opened + len(parts[0][1]) + 1 + len(parts[1][1])) if len(parts) > 1 else None
        windows.append((f, at, at, parts[0][1].strip(), future))
    windows += [(f, at, _written_at(code, at, expr.strip()), expr.strip(), None) for f, at, expr in asserts if f.line in tested]
    out = []
    for f, at, read_at, window, future in windows:
        if HANG_BOUND.fullmatch(window):
            continue
        scope = _scope_at(path, code, read_at, consts)
        timers, chain = named_budgets(window, read_at, code, scope, budgets)
        if timers:
            t = timers[0]
            source = f"{t.name} (def {t.path}:{t.line}, {t.seconds:g} s)"
            out.append((f, at, f"{PRODUCT_BUDGET} the bound is written from {source}: {ADVICE}", chain, f"named {source}"))
            continue
        bound = resolve(window, scope)
        calls, held_lines = carriers(code, *future, budgets) if future else ([], set())
        # Every Duration handed to every carried call counts; each is resolved
        # where its call is written.
        given = [
            (v[0], fn)
            for fn, args, paren in calls
            for _, a in split_top(args, (",",))
            if not HANG_BOUND.search(a) and (v := _argument_value(path, code, a.strip(), paren, consts)) and v[1]
        ]
        if bound is not None and given and bound[0] <= max(given)[0]:
            longest, fn = max(given)
            rule = f"{PRODUCT_BUDGET} the bound is at most the explicit budget {longest:g} s passed to {fn} at :{f.line}: {ADVICE}"
            out.append((f, at, rule, held_lines, f"<= explicit budget passed to {fn} at :{f.line} ({longest:g} s)"))
            continue
        if bound is None or not ONE_DURATION.fullmatch(window) or bound[0] >= FLOOR_S:
            continue
        imported = imports_of(code)
        for name, defs in sorted(budgets.consts.items()):
            reach = {p for p, _ in candidates(name, imported.get(name, ""), scope)} | {path}
            same = next((Named(name, p, n, s) for p, n, s in defs if s == bound[0] and p in reach), None)
            if same:
                out.append((f, at, "", set(), f"equals {same.name} in scope (def {same.path}:{same.line}, {same.seconds:g} s)"))
                break
    return out


def budget_list(path, text, consts, includers, budgets) -> list[str]:
    """The whole-tree audit lines: every site of each shape, old or new."""
    return [f"BUDGET LIST {f.path}:{f.line} ({f.fn}): {what}" for f, _, _, _, what in budget_sites(path, text, consts, includers, budgets)]


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
# `vs <timer> (<ticket>)`, or `vs <timer> (why: <reason>)` on new lines, which may not carry a
# ticket id (the public-repo check refuses them). The reason is non-empty and has no `)`.
ORACLE_FORMAT = re.compile(r"^\s*vs\s+(.*?\S)\s*\((?:MIK-\d+|why:\s*[^\s)][^)]*)\)\s*$")
ORACLE_SUBJECT = re.compile(r"\d+(?:\.\d+)?\s*(?:s|ms|us|ns)\b|\b[A-Z][A-Z0-9_]{2,}\b")
SLEEP_CALL = re.compile(r"(?<![\w.])(?:(?:tokio|std)::(?:time|thread)::|time::|thread::)?sleep\(")


def comment_on(lines: list[str], line: int, pattern: re.Pattern) -> re.Match | None:
    """`pattern` in a comment on 1-based `line` or the line above it."""
    for n in (line, line - 1):
        if 1 <= n <= len(lines) and (m := pattern.search(lines[n - 1])):
            return m
    return None


def binding_lines(code: str, expr: str, at: int) -> list[int]:
    """Lines of the `let` or `const` each plain name in `expr` refers to at
    offset `at` (the binding visible there, not the file's last of the name)."""
    found = []
    for name in set(re.findall(r"\b[A-Za-z_]\w*\b", expr)):
        if (spot := visible_binding(code, name, at)) is not None:
            found.append(code.count("\n", 0, spot) + 1)
    return found


def oracle_covers(text: str, line: int, expr: str) -> bool:
    """A well-formed `timing-oracle:` at the window's line or at the binding of
    a name its window expression uses (C: "at its constant or call")."""
    raw, code = text.splitlines(), blank_strings_and_comments(text)
    for n in [line, *binding_lines(code, expr, line_offset(code, line))]:
        if (m := comment_on(raw, n, ORACLE_LINE)) and not oracle_malformed(m):
            return True
    return False


def statement_end(code: str, line: int) -> int:
    """The line where the statement starting on `line` ends (`statement_close`:
    its own `;`, past any block or call it opens)."""
    return code.count("\n", 0, statement_close(code, line_offset(code, line))) + 1


def oracle_malformed(m: re.Match) -> bool:
    """True when a `timing-oracle:` comment does not name a timer and a ticket or a reason."""
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
        # The signature's own body finder, so a braced const generic
        # (`-> Probe<{ 1 + 1 }>`) is not the body; a signature it does not
        # support falls back to the first `{`, as before.
        brace = _signature_body(code, m.end())
        if brace is None:
            brace = code.find("{", m.end())
            semi = code.find(";", m.end())
            if brace < 0 or 0 <= semi < brace:
                continue
        elif brace < 0:
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
    budgets: Budgets | None = None,
) -> list[Finding]:
    """PR-C's rules on the spans of `text` that touch an `added` line."""
    code = blank_strings_and_comments(text)
    tested = test_lines(path, text)
    if not tested or not added:
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
        if (m := TAG_LINE.search(raw[n - 1])) and n in tested:
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
        # The floor judges test code only, as the shapes below do; full mode
        # keeps judging an elapsed assert anywhere in a file.
        if f.line not in tested:
            continue
        # New when any line of the statement changed, or the binding of a name
        # its window uses (#3746 review).
        span = range(f.line, statement_end(code, f.line) + 1)
        new = any(n in added for n in span) or any(n in added for n in binding_lines(code, f.assertion, line_offset(code, f.line)))
        if new and (f.path, f.fn, f.assertion) not in carried and not HANG_BOUND.search(f.assertion) and not oracle_ok(f.line, f.assertion):
            found.append(f._replace(rule=FLOOR))
    # The product-timer rule, on the same notion of new (and along the chain
    # of bindings its window was derived through).
    for f, at, rule, chain, _ in budget_sites(path, text, consts, includers, budgets) if budgets else ():
        span = range(f.line, statement_end(code, f.line) + 1)
        reads = set(binding_lines(code, f.assertion, at)) | chain
        if rule and (added & set(span) or added & reads) and (f.path, f.fn, f.assertion) not in carried and not oracle_ok(f.line, f.assertion):
            found.append(f._replace(rule=rule))
    return found + scan_new_shapes(path, code, raw, tested, added, Scope(path, {}, file_consts, consts, imports), oracle_ok, tag_ok)


def scan_new_shapes(path, code, raw, tested, added, scope, oracle_ok, tag_ok) -> list[Finding]:
    """v2's sleep and expected-elapse shapes, B's loops, G's poll budget, D's timer."""
    found: list[Finding] = []
    line_of = lambda at: code.count("\n", 0, at) + 1  # noqa: E731
    touches = lambda a, b: any(n in added for n in range(a, b + 1))  # noqa: E731
    for attr_at, fn, body_open, body_end in fn_spans(code):
        if tested.isdisjoint(range(line_of(attr_at), line_of(body_end) + 1)) or paused_clock(code, attr_at, body_end):
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
            span_new = touches(min(line, line_of(min(later))), last) or (def_line_in(code, expr, line_of, at) in added)
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
    # A product fn can hold a test-only statement: only its sites are judged.
    return [f for f in found if f.line in tested]


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
        bound = def_line_in(code, expr, line_of, start)
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


def def_line_in(code: str, expr: str, line_of, at: int) -> int | None:
    """The line of the `let` or `const` a plain-name `expr` refers to at `at`."""
    name = expr.strip()
    if not re.fullmatch(r"\w+", name):
        return None
    spot = visible_binding(code, name, at)
    return None if spot is None else line_of(spot)
