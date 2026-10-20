#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Report killer-test drift between two revisions (MIK-8565).

    c6_killer_drift.py --base REV --head REV MANIFEST

MANIFEST is a c6_resolve.py manifest TSV: line 1 is ``head_sha\\t<sha>`` and each
row is ``id\\tplatform\\tpatch\\tcargo args``. The killer test's name is the last
argument's last ``::`` segment.

For each row the test function ``fn <name>`` is found at ``--base`` and at
``--head`` with ``git grep -n -w "fn <name>" <rev> -- '*.rs'``; there must be
exactly one match per rev, else the row is MISSING (none) or AMBIGUOUS (more
than one). Its body is extracted with a brace-matching scanner starting at the
first ``{`` after the match, ignoring braces in string literals, raw strings,
char literals and comments, including attribute lines and doc comments directly
above it. Base and head text are compared with trailing whitespace stripped per
line.

Prints one line per row (``<id>\\t<STATUS>\\t<file>``) and a summary line.
Exits 0 only when every row is UNCHANGED, else 1, so the operator re-runs those
rows. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

_CHAR_RE = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")
_FN_RE = re.compile(r"\bfn\b")


def _is_raw_start(text: str, i: int) -> bool:
    """True when a raw string opens at i: ``r"..."`` or ``r#"..."#`` etc."""
    if text[i] != "r":
        return False
    if i and (text[i - 1].isalnum() or text[i - 1] == "_"):
        return False
    j = i + 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def extract_fn(text: str, start_index: int) -> str:
    """The function at ``start_index`` (a ``fn <name>`` match) through its body.

    Starts at the first ``{`` after ``start_index`` and returns the text from any
    attribute lines and doc comments directly above the ``fn`` line to the
    matching closing brace, inclusive. Braces inside string literals (``"..."``
    with escapes), raw strings (``r"..."``, ``r#"..."#``), char literals and
    ``//`` and ``/* */`` comments do not count.
    """
    brace_open = text.find("{", start_index)
    if brace_open < 0:
        raise ValueError("no opening brace after start_index")
    segment = text[start_index:brace_open]
    matches = list(_FN_RE.finditer(segment))
    fn_offset = start_index + matches[-1].start() if matches else start_index

    lines = text.splitlines(keepends=True)
    fn_line = 0
    offset = 0
    for i, ln in enumerate(lines):
        if offset <= fn_offset < offset + len(ln):
            fn_line = i
            break
        offset += len(ln)
    else:
        fn_line = len(lines) - 1 if lines else 0
    start_line = fn_line
    while start_line > 0:
        prev = lines[start_line - 1].strip()
        if prev.startswith("#") or prev.startswith("///") or prev.startswith("//!"):
            start_line -= 1
        else:
            break
    result_start = sum(len(ln) for ln in lines[:start_line])

    depth = 0
    i, n = brace_open, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0:
                raise ValueError("unterminated function body")
            i = j + 1
            continue
        if text.startswith("/*", i):
            level, j = 1, i + 2
            while j < n and level:
                if text.startswith("/*", j):
                    level, j = level + 1, j + 2
                elif text.startswith("*/", j):
                    level, j = level - 1, j + 2
                else:
                    j += 1
            if level:
                raise ValueError("unterminated block comment")
            i = j
            continue
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated string")
            i = j + 1
            continue
        if c == "r" and _is_raw_start(text, i):
            k = i + 1
            while text[k] == "#":
                k += 1
            close = '"' + text[i + 1:k]
            j = text.find(close, k + 1)
            if j < 0:
                raise ValueError("unterminated raw string")
            i = j + len(close)
            continue
        if c == "'":
            m = _CHAR_RE.match(text, i)
            if m:
                i = m.end()
                continue
            i += 1
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return text[result_start:i]
            if depth < 0:
                raise ValueError("unbalanced closing brace")
            continue
        i += 1
    raise ValueError("unterminated function body")


def _git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def _grep(rev: str, name: str) -> list[tuple[str, int]]:
    """The (file, line) of every ``fn <name>`` at ``rev``."""
    done = _git(["grep", "-n", "-w", f"fn {name}", rev, "--", "*.rs"])
    if done.returncode not in (0, 1):
        raise RuntimeError(f"git grep: {done.stderr.strip()}")
    hits = []
    for line in done.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[2].isdigit():
            hits.append((parts[1], int(parts[2])))
        elif len(parts) >= 3 and parts[1].isdigit():
            hits.append((parts[0], int(parts[1])))
    return hits


def _show(rev: str, path: str) -> str:
    done = _git(["show", f"{rev}:{path}"])
    if done.returncode:
        raise RuntimeError(f"git show {rev}:{path}: {done.stderr.strip()}")
    return done.stdout


def _fn_start(text: str, lineno: int, name: str) -> int:
    lines = text.splitlines(keepends=True)
    if lineno < 1 or lineno > len(lines):
        raise ValueError(f"line {lineno} out of range")
    line_start = sum(len(ln) for ln in lines[:lineno - 1])
    line = lines[lineno - 1]
    at = line.find(f"fn {name}")
    if at >= 0:
        return line_start + at
    at = line.find("fn")
    if at >= 0:
        return line_start + at
    return line_start


def _normalize(body: str) -> str:
    return "\n".join(line.rstrip() for line in body.splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True, help="revision the killers were recorded at")
    parser.add_argument("--head", required=True, help="revision to compare against")
    parser.add_argument("manifest", help="c6_resolve.py manifest TSV")
    args = parser.parse_args(argv)

    with open(args.manifest, encoding="utf-8") as f:
        raw = f.read()
    lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines or not lines[0].startswith("head_sha\t"):
        print("manifest line 1 must be head_sha<TAB><sha>", file=sys.stderr)
        return 2
    rows = []
    for line in lines[1:]:
        parts = line.split("\t", 3)
        if len(parts) != 4:
            print(f"bad manifest row: {line!r}", file=sys.stderr)
            return 2
        rid = parts[0].strip()
        argv = parts[3].split()
        name = argv[-1].split("::")[-1] if argv else ""
        rows.append((rid, name))

    changed = bad = 0
    try:
        for rid, name in rows:
            if not name:
                print(f"{rid}\tMISSING\t-")
                bad += 1
                continue
            base_hits = _grep(args.base, name)
            head_hits = _grep(args.head, name)
            if len(base_hits) != 1 or len(head_hits) != 1:
                status = "AMBIGUOUS" if len(base_hits) > 1 or len(head_hits) > 1 else "MISSING"
                where = head_hits[0][0] if len(head_hits) == 1 else "-"
                print(f"{rid}\t{status}\t{where}")
                bad += 1
                continue
            try:
                base_text = _show(args.base, base_hits[0][0])
                base_body = extract_fn(base_text, _fn_start(base_text, base_hits[0][1], name))
                head_text = _show(args.head, head_hits[0][0])
                head_body = extract_fn(head_text, _fn_start(head_text, head_hits[0][1], name))
            except (RuntimeError, ValueError):
                print(f"{rid}\tMISSING\t{head_hits[0][0]}")
                bad += 1
                continue
            if _normalize(base_body) == _normalize(head_body):
                print(f"{rid}\tUNCHANGED\t{head_hits[0][0]}")
            else:
                print(f"{rid}\tCHANGED\t{head_hits[0][0]}")
                changed += 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"killer drift: {changed} changed, {bad} missing/ambiguous, of {len(rows)} rows")
    return 0 if changed == 0 and bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
