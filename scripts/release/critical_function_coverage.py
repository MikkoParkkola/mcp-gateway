#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade each Critical function's own line coverage (MIK-7324.COV.3).

Reads the function inventory (docs/release/v4.0.0-critical-functions.tsv plus its
docs/release/inventory.d/*.critical.tsv fragments, through inventory_ledger.py) and
one or more lcov reports from `cargo llvm-cov report --lcov`. A function's
lines are the `DA:` records from its `fn` line to the brace that closes its
body; its coverage is the share of those with a non-zero count, over the union
of the reports. Give one report per platform run (Linux and Windows), so a
`#[cfg(windows)]` function is graded by the run that compiles it.

Tracing macro arguments: a plain field (a literal, identifier or path value) on its own line inside
`trace!`/`debug!`/`info!`/`warn!`/`error!`/`event!`/`span!` is compiled twice,
once for the subscriber and once into tracing's log-fallback branch, and the
instrument attributes such lines to a region that reads zero even when the
event was emitted. Those argument lines are excluded, but only when the
macro's head line has a non-zero count (the call was reached); every excluded
line is printed with its head count so the exclusion can be audited.

A call (or any non-plain argument) on a macro's head line
(`debug!(url = %clean(x), ..)`) is the reverse case: it shares the head line, so the head's count says the
macro was reached, not that the call ran. Such a head line is graded as missed
whatever its count and listed as unverifiable (MIK-7725), so the rule can fail
spuriously but never pass an unrun call. Compute the value into a local before
the macro and pass the local.

Exit status: 0 when every Critical row clears the floor, 1 otherwise. A row
whose function is gone, or that no given report measured, fails. 3 when a
given report is absent, empty, unreadable or unparseable: nothing was graded
(MIK-8265).
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_ledger as ledger  # noqa: E402

FLOOR = 95.0


def strip_literals(line):
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])'", "''", line)
    return line.split("//", 1)[0]


def body_range(lines, start):
    """1-based inclusive range from the `fn` line to its closing brace."""
    depth, seen = 0, False
    for i in range(start - 1, len(lines)):
        code = strip_literals(lines[i])
        if not seen and ";" in code and "{" not in code:
            return start, i + 1
        depth += code.count("{") - code.count("}")
        seen = seen or "{" in code
        if seen and depth <= 0:
            return start, i + 1
    return start, len(lines)


TRACING_MACRO = re.compile(
    r"(?<![\w:])(?:tracing::)?(trace|debug|info|warn|error|event|span)!\s*\("
)


# The only argument lines ever excluded (a whitelist; everything else stays
# graded): exactly one field, `[name =] [%|?]value,`, where the value is a
# literal, a bare identifier, or a field/path access (`a.b`, `a::b`). No call,
# parenthesis, operator, postfix `?`, closure or macro. Literals are already
# blanked by strip_literals, so a string or char shows as `""` / `''`.
_PATH = r"[A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)*"
_VALUE = r"(?:" + _PATH + r'|""|\'\'|-?\d[\w.]*)'
PLAIN_FIELD = re.compile(
    r"^(?:[A-Za-z_][\w.]*\s*=\s*)?[%?]?" + _VALUE + r"\s*,$"
)


# A head line is verifiable only when the WHOLE line has one plain shape:
# indent, an optional `tracing::` path, a level macro and `!(`, then
# comma-separated plain items (a quote-free string literal, `name = [%|?]value`,
# or a bare `[%|?]value`, where a value is an identifier path or a number), an
# optional trailing comma, and an optional `)` and `;`. Any other line holding a
# tracing macro name is unverifiable: a second statement, a char literal, a raw
# string, a comment, another delimiter, a call. One anchored match, no
# stripping or parsing, so there is no preprocessing step to fool. Spurious
# fails are possible; an unrun call passing is not.
_LEVELS = ("trace", "debug", "info", "warn", "error", "event", "span")
# A head-line value is an identifier or `::` path, or a numeric literal. No `.`:
# a field access can run user Deref code, which this line's count cannot vouch
# for. (The argument-line rule above keeps its own, separately ruled whitelist.)
_HEAD_PATH = r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*"
_NUMBER = r"-?\d[\d_]*(?:\.\d[\d_]*)?(?:[iuf](?:8|16|32|64|128|size))?"
_ITEM_VALUE = r"[%?]?(?:" + _HEAD_PATH + r"|" + _NUMBER + r")"
_ITEM = r'(?:"[^"\\]*"|[A-Za-z_]\w*\s*=\s*' + _ITEM_VALUE + r"|" + _ITEM_VALUE + r")"
# An optional leading `target: X,` names the event's target. X is a constant
# path or a quote-free literal (`tracing` requires a constant there), so it
# runs no code: a module pins its moved events to one target this way.
_TARGET = r'(?:target\s*:\s*(?:' + _HEAD_PATH + r'|"[^"\\]*")\s*,\s*)?'
PLAIN_HEAD = re.compile(
    r"^\s*(?:(?:::)?tracing::)?(?:trace|debug|info|warn|error|event)!\(\s*"
    + _TARGET +
    r"(?:" + _ITEM + r"(?:\s*,\s*" + _ITEM + r")*\s*,?)?"
    r"\s*(?:\)\s*;?)?\s*$"
)
TRACING_NAME = re.compile(
    r"(?<!\w)(?:" + "|".join(_LEVELS) + r")\s*(?:/\*.*?\*/\s*)*!"
)
# The head-line rule recognises a tracing macro by its name. Two things could
# hide one under another name, and neither is parsed (parsing is what kept
# leaking):
# - A renaming `use` of a tracing item: the grade fails closed (INDIRECT) on
#   any `use` that mentions tracing and holds `as` not followed by `_`.
# - A `macro_rules!` wrapper: every macro defined in `src/` is treated as a
#   possible tracing macro, so a line invoking one in a Critical function is
#   unverifiable (only a level macro can match PLAIN_HEAD).
_GAP = r"(?:\s|/\*.*?\*/|//[^\n]*\n)*"
_USE_STATEMENT = re.compile(r"(?<!\w)use\b[^;]*;", re.S)
_RENAMING = re.compile(r"\bas\b(?!\s*_(?!\w))")
_MACRO_DEF = re.compile(r"(?<!\w)macro_rules" + _GAP + r"!" + _GAP + r"(?:r#)?(\w+)", re.S)


def tracing_indirections(root):
    """`file: what` for each renaming `use` of a tracing item in `src/`."""
    found = []
    for path in sorted((Path(root) / "src").rglob("*.rs")):
        for use in _USE_STATEMENT.findall(path.read_text()):
            if "tracing" in use and _RENAMING.search(use):
                found.append(f"{path.relative_to(root).as_posix()}: renaming use of a tracing item")
    return found


# Macros known not to log, so a line invoking only these is graded by its count.
# Any other macro (a level macro, a local `macro_rules!`, or one from a crate
# that might wrap tracing) puts the line under PLAIN_HEAD. A local definition
# that shadows one of these names takes it off the list.
SAFE_MACROS = frozenset({
    "assert", "assert_eq", "assert_ne", "concat", "debug_assert", "debug_assert_eq",
    "debug_assert_ne", "env", "eprintln", "format", "format_args", "include_str",
    "json", "matches", "panic", "print", "println", "stringify", "unimplemented",
    "unreachable", "vec", "write", "writeln", "counter",
})
# `if !(..)`, `return !(..)`: a keyword before `!` is a negation, not a macro.
_KEYWORDS = frozenset({
    "if", "else", "while", "match", "return", "in", "let", "for", "loop", "move",
    "break", "continue", "as", "mut", "ref", "await", "async", "unsafe", "yield",
})
# The path before a macro's name is captured: `other::format!` is not the
# built-in `format!` (MIK-7864), so only an unqualified name, or one qualified
# by a standard crate, is looked up in the safe list. A single colon before
# the path (`{"k":other::format!(..)}`) is punctuation, not part of it.
_ANY_MACRO = re.compile(
    r"(?<!\w)(?<!::)((?:::" + _GAP + r")?(?:(?:r#)?\w+" + _GAP + r"::" + _GAP + r")*)"
    r"(?:r#)?(\w+)" + _GAP + r"!" + _GAP + r"[(\[{]",
    re.S,
)
_STANDARD_PATHS = frozenset({"", "std::", "core::", "alloc::"})
# Exact paths only. `telemetry_metrics` is the `metrics` crate under the name
# Cargo.toml gives it; its `counter!` records a metric and does not log.
_QUALIFIED_SAFE = frozenset({"serde_json::json", "telemetry_metrics::counter"})
_GAP_TEXT = re.compile(r"\s|/\*.*?\*/|//[^\n]*\n", re.S)


def is_safe_macro(prefix, name, safe):
    """Whether `prefix` + `name` is a macro known not to log."""
    path = _GAP_TEXT.sub("", prefix).removeprefix("::")
    if path in _STANDARD_PATHS:
        return name in safe
    return path + name in _QUALIFIED_SAFE and name in safe


def macro_names(root):
    """The macro names a line may invoke and still be graded by its count:
    SAFE_MACROS minus any name a `macro_rules!` in `src/` defines."""
    local = set()
    for path in (Path(root) / "src").rglob("*.rs"):
        local.update(_MACRO_DEF.findall(path.read_text()))
    return SAFE_MACROS - local


# MIK-8327: a line that is only an optional `let <pattern> =` and a
# `[::]tokio::select! {` head holds no call: each arm is graded on its own
# line, and a binding pattern runs no code. Such a line is graded by its
# count, so a reached head is hit and an unreached one missed. Anything else
# on the line (`biased;`, an arm, a call, a type annotation, a comment,
# another path, a bare `select!`) keeps the MIK-7725 rule. The spelling only
# names tokio's macro if nothing in the crate can rebind it, so the exemption
# is off for the whole grade when `src/` holds a `mod tokio`, an `as tokio`,
# an `as select` or a `macro_rules! select`, or Cargo.toml renames the tokio
# dependency (`package =`): any of those could make the head a wrapper whose
# expansion runs code on the head line's count.
_BINDING = r"(?:mut\s+)?[A-Za-z_]\w*"
_PATTERN = r"(?:" + _BINDING + r"|\(\s*" + _BINDING + r"(?:\s*,\s*" + _BINDING + r")*\s*,?\s*\))"
SELECT_HEAD = re.compile(
    r"^\s*(?:let\s+" + _PATTERN + r"\s*=\s*)?(?:::)?tokio::select!\s*\{\s*$"
)
_REBINDS_SELECT = re.compile(
    r"(?<!\w)mod\s+tokio\b|\bas\s+(?:tokio|select)\b|(?<!\w)macro_rules" + _GAP + r"!" + _GAP + r"select\b",
    re.S,
)
# An inline `tokio = { package = .. }`, or any `[...dependencies.tokio]` table
# (which could carry a `package` key on a later line): either fails closed.
_TOKIO_RENAMED = re.compile(
    r"(?m)^\s*tokio\s*=\s*\{[^}\n]*\bpackage\s*=|^\s*\[[^\]\n]*dependencies\.tokio\s*\]"
)


def select_head_trusted(root):
    """Whether `tokio::select!` can only name tokio's macro in this crate."""
    if any(_REBINDS_SELECT.search(path.read_text()) for path in (Path(root) / "src").rglob("*.rs")):
        return False
    cargo = Path(root) / "Cargo.toml"
    return not (cargo.exists() and _TOKIO_RENAMED.search(cargo.read_text()))


def head_has_call(raw, safe=SAFE_MACROS, select_trusted=False):
    """True when this raw source line invokes a macro outside `safe` (or names
    a tracing level) but is not, as a whole, a plain head line (see above)."""
    if select_trusted and SELECT_HEAD.match(raw):
        return False
    unsafe = TRACING_NAME.search(raw) or any(
        not is_safe_macro(prefix, name, safe) and not (prefix == "" and name in _KEYWORDS)
        for prefix, name in _ANY_MACRO.findall(raw)
    )
    return bool(unsafe) and not PLAIN_HEAD.match(raw)


def split_call_lines(lines, lo, hi, safe=SAFE_MACROS):
    """Lines lo..hi spanned by a macro call (outside `safe`) or a tracing name
    whose name and delimiter sit on different lines (MIK-7864): a per-line scan
    never sees one. Every line of such a span is graded as unverifiable."""
    text = "\n".join(lines[lo - 1:hi])
    spans = [
        m.span()
        for m in _ANY_MACRO.finditer(text)
        if not is_safe_macro(m.group(1), m.group(2), safe)
        and not (m.group(1) == "" and m.group(2) in _KEYWORDS)
    ]
    spans += [m.span() for m in TRACING_NAME.finditer(text)]
    found = set()
    for start, end in spans:
        first = lo + text.count("\n", 0, start)
        last = lo + text.count("\n", 0, end)
        if last > first:
            found.update(range(first, last + 1))
    return found


def is_plain_field(code):
    return bool(PLAIN_FIELD.match(code.strip()))


def macro_argument_lines(lines, lo, hi):
    """(head, argument lines) for each tracing macro call inside lo..hi."""
    calls = []
    for head in range(lo, hi + 1):
        code = strip_literals(lines[head - 1])
        match = TRACING_MACRO.search(code)
        if not match:
            continue
        depth = 0
        for n in range(head, hi + 1):
            text = strip_literals(lines[n - 1])
            if n == head:
                text = text[match.end() - 1 :]
            depth += text.count("(") - text.count(")")
            if depth <= 0:
                simple, nesting, fresh = [], 0, True
                for m in range(head + 1, n + 1):
                    code = strip_literals(lines[m - 1])
                    text = code.strip()
                    if not text:
                        # A blank or comment-only line carries no token: it
                        # neither starts nor ends an argument.
                        continue
                    # Only a whole field on its own line, at the argument
                    # list's own level: it starts a fresh argument and ends
                    # with its comma. A continuation (`&& check(),`), a line
                    # left open (`flag = a`) or anything inside a nested
                    # block, call or array is logic, not a field.
                    if nesting == 0 and fresh and is_plain_field(code):
                        simple.append(m)
                    nesting += sum(code.count(c) for c in "({[") - sum(code.count(c) for c in ")}]")
                    nesting = max(nesting, 0)
                    fresh = nesting == 0 and text.endswith(",")
                calls.append((head, simple))
                break
    return calls


def fn_line(lines, name, occurrence):
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    hits = [i + 1 for i, line in enumerate(lines) if pattern.search(line)]
    return hits[occurrence - 1] if len(hits) >= occurrence else None


def repo_relative(source, root):
    """The `src/...` path of an lcov `SF:` entry, as it exists under `root`.

    Reports from different platforms carry different absolute prefixes, and a
    checkout may itself sit under a directory named `src`, so the first `/src/`
    is not the repository boundary: take the first `src/...` suffix that names
    a file in this checkout.
    """
    source = source.replace("\\", "/")
    parts = source.split("/")
    for i, part in enumerate(parts):
        if part == "src":
            candidate = "/".join(parts[i:])
            if (Path(root) / candidate).is_file():
                return candidate
    return None


# Exit status when an input report is absent: neither a pass (0), a graded
# FAIL (1) nor a usage error (2), so a caller cannot read it as a grade (MIK-8265).
INPUT_MISSING = 3


class MissingInput(Exception):
    """An lcov report the grade was given is absent, empty, unreadable or
    unparseable, as
    when a platform's coverage job uploaded none. Nothing is graded from a
    partial set: an empty report would grade as the other platform alone."""

    def __init__(self, path):
        super().__init__(f"input missing: {path}")
        self.path = str(path)


def read_lcov(paths, root):
    texts = []
    for path in paths:
        try:
            text = Path(path).read_text() if Path(path).is_file() else ""
        except OSError:
            text = ""
        if not text.strip():
            raise MissingInput(path)
        texts.append(text)
    hits, current = {}, None
    for path, text in zip(paths, texts):
        for raw in text.splitlines():
            if raw.startswith("SF:"):
                current = repo_relative(raw[3:], root)
                if current:
                    hits.setdefault(current, {})
            elif raw.startswith("DA:") and current:
                try:
                    number, count = raw[3:].split(",")[:2]
                    line, count = int(number), int(count)
                except ValueError:
                    raise MissingInput(path) from None  # unparseable: a corrupt report
                hits[current][line] = hits[current].get(line, 0) + count
    return hits


def read_inventory(path):
    """The critical ledger: `path` plus the `*.critical.tsv` fragments beside it,
    through inventory_ledger.py (MIK-8279). Raises LedgerError on any bad row."""
    return ledger.load_files(ledger.CRITICAL, Path(path))


def grade(root, inventory, lcovs):
    hits = read_lcov(lcovs, root)
    names = macro_names(root)
    select_trusted = select_head_trusted(root)
    results = [
        ("INDIRECT", {"path": what.split(":", 1)[0], "fn": what.split(": ", 1)[1], "occurrence": "-"}, None, None, [])
        for what in tracing_indirections(root)
    ]
    for row in read_inventory(inventory):
        if row["tier"] != "critical":
            continue
        source = Path(root) / row["path"]
        lines = source.read_text().splitlines() if source.exists() else []
        start = fn_line(lines, row["fn"], int(row["occurrence"]))
        if start is None:
            results.append(("MISSING", row, None, None, []))
            continue
        lo, hi = body_range(lines, start)
        counts = {n: c for n, c in hits.get(row["path"], {}).items() if lo <= n <= hi}
        if not counts:
            results.append(("UNMEASURED", row, lo, hi, []))
            continue
        unverifiable = []
        split = split_call_lines(lines, lo, hi, names)
        for n in range(lo, hi + 1):
            if n in counts and (n in split or head_has_call(lines[n - 1], names, select_trusted)):
                unverifiable.append(f"{row['path']}:{n} (head count {counts[n]})")
                counts[n] = 0
        excluded = []
        for head, arguments in macro_argument_lines(lines, lo, hi):
            if hits[row["path"]].get(head, 0) > 0:
                for n in arguments:
                    if n in counts and counts[n] == 0:
                        del counts[n]
                        excluded.append(f"{row['path']}:{n} (head {head}={hits[row['path']][head]})")
        covered = sum(1 for c in counts.values() if c > 0)
        missed = sorted(n for n, c in counts.items() if c == 0)
        pct = 100.0 * covered / len(counts)
        status = "ok" if pct >= FLOOR else "BELOW"
        results.append((status, row, lo, hi, missed, covered, len(counts), pct, excluded, unverifiable))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--inventory", default="docs/release/v4.0.0-critical-functions.tsv")
    parser.add_argument("--lcov", action="append", required=True, help="repeat per platform run")
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--scope",
        choices=("all-platforms", "linux-only"),
        default="all-platforms",
        help="linux-only: the reports cover Linux alone (a pull request's CI grade), so a"
        " row with no measured line, a function compiled only on Windows, does not fail;"
        " the release-line grade uses all-platforms (MIK-8217)",
    )
    args = parser.parse_args(argv)

    failed = graded = not_here = 0
    try:
        results = grade(args.root, args.inventory, args.lcov)
    except ledger.LedgerError as error:
        for problem in error.problems:
            print(f"inventory: {problem}")
        print("the inventory could not be read; nothing was graded")
        return 1
    except MissingInput as missing:
        print(missing)
        print("NOT GRADED: a coverage report is missing, so no Critical row was graded")
        return INPUT_MISSING
    for result in results:
        status, row = result[0], result[1]
        # An INDIRECT result is a diagnostic about the tree, not an inventory row.
        graded += status != "INDIRECT"
        where = f"{row['path']}:{row['fn']}#{row['occurrence']}"
        if status in ("ok", "BELOW"):
            _, _, lo, hi, missed, covered, total, pct, excluded, unverifiable = result
            print(f"{status}\t{pct:6.2f}%\t{covered}/{total}\t{where}\tlines {lo}-{hi}\tmissed={missed}")
            for line in excluded:
                print(f"  excluded tracing argument line {line}")
            for line in unverifiable:
                print(f"  unverifiable tracing head line {line}: graded missed")
            failed += status == "BELOW"
        elif status == "UNMEASURED" and args.scope == "linux-only":
            print(f"UNMEASURED-HERE\t-\t-\t{where}")
            not_here += 1
        else:
            print(f"{status}\t-\t-\t{where}")
            failed += 1
    # The Critical count lives here, read from the inventory, and nowhere
    # else (MIK-8195): a count copied into a doc goes stale with every wave.
    print(f"critical rows graded: {graded}")
    if args.scope == "linux-only":
        print(f"critical rows not measured in this scope: {not_here}")
    print(f"critical rows failing: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
