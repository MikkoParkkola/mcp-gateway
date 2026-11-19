#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Text pre-check for two clippy lints that cost a Spark lint round when they slip through (no compile needed).

  too_many_lines   a fn body with more than LIMIT non-blank, non-comment lines between its braces (clippy's own
                   limit, 100; calibrated on this tree: a 102-line fn counted brace to brace passes clippy). An `allow(...too_many_lines)`
                   on the fn, or `#![allow(...too_many_lines)]` in the file, exempts it.
  format_push_string  `push_str(&format!(` and `+= &format!(`.

Usage: check_clippy_textlints.py [--self-test] [paths or dirs; default: tracked *.rs under src tests benches examples]
Output: file:line: message, exit 1 when any. Approximate by design: clippy stays the authority; this only saves the
queue round for the common cases."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

LIMIT = 100
# Files clippy never compiles, so a long fn there is not a finding (each with its reason).
EXEMPT = {
    "src/commands/api_matrix_tests.rs": "module gated by cfg(tp2), which no clippy run enables",
}
FMT = re.compile(r"push_str\(\s*&format!\(|\+=\s*&format!\(")
FN = re.compile(r"\bfn\s+[A-Za-z_]\w*")
ALLOW = re.compile(r"too_many_lines")


def mask(src: str) -> str:
    """Same length and same newlines; comments become spaces, string/char contents become 'x'."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j): depth += 1; j += 2
                elif src.startswith("*/", j): depth -= 1; j += 2
                else: j += 1
            out.append("".join("\n" if ch == "\n" else " " for ch in src[i:j])); i = j
        elif c in "rbc" and re.match(r'[bc]?r#*"', src[i:i + 12]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            rm = re.match(r'[bc]?r(#*)"', src[i:])
            h = rm.group(1)
            end = src.find('"' + h, i + rm.end())
            j = n if end < 0 else end + 1 + len(h)
            out.append("".join("\n" if ch == "\n" else "x" for ch in src[i:j])); i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join("\n" if ch == "\n" else "x" for ch in src[i:j])); i = j
        elif c == "'" and re.match(r"'(\\.[^']*|[^\\'])'", src[i:i + 12]):
            j = re.match(r"'(\\.[^']*|[^\\'])'", src[i:]).end() + i
            out.append("x" * (j - i)); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def check(path: str, src: str) -> list[str]:
    found = []
    m = mask(src)
    lines, mlines = src.splitlines(), m.splitlines()
    for fm in FMT.finditer(m):  # whole masked source, so a call split over lines is found too
        found.append(f"{path}:{m.count(chr(10), 0, fm.start()) + 1}: format_push_string: use write!(s, ...) (std::fmt::Write), not push_str(&format!(..))")
    if re.search(r"#!\[(allow|expect|cfg_attr)[^\]]*too_many_lines", m):  # masked: a comment or doc example never counts
        return found
    for fm in FN.finditer(m):
        i, depth = fm.end(), 0
        while i < len(m) and not (depth == 0 and m[i] in "{;"):
            depth += m[i] in "([" ; depth -= m[i] in ")]"; i += 1
        if i >= len(m) or m[i] != "{":
            continue
        start, depth = i, 0
        while i < len(m):
            depth += m[i] == "{"; depth -= m[i] == "}"; i += 1
            if depth == 0:
                break
        first, last = m.count("\n", 0, start), m.count("\n", 0, i - 1)
        body = sum(1 for l in mlines[first + 1:last] if l.strip())  # clippy drops the brace lines: its count is the lines between them
        fn_line = m.count("\n", 0, fm.start())
        above = []  # the attribute block above the fn: back to the previous item's end ('}' or ';')
        for k in range(fn_line - 1, max(fn_line - 40, -1), -1):
            if mlines[k].rstrip().endswith(("}", ";")):
                break
            above.append(mlines[k])  # masked: an allow named in a comment never counts
        chunk = "\n".join(above) + "\n" + mlines[fn_line]  # the fn's own line too: #[allow(..)] fn f() {
        # #[tokio::test] rewrites the fn, and clippy then skips it (a 300-line one passes in this tree).
        if body > LIMIT and not ALLOW.search(chunk) and "tokio::test" not in chunk:
            found.append(f"{path}:{fn_line + 1}: too_many_lines: {fm.group(0)} has {body} code lines (limit {LIMIT})")
    return found


def stale_exempt(exists) -> list[str]:
    """An exempt path that no longer exists is a finding, so the list cannot rot."""
    return [f"{p}: stale exemption (file gone; remove it from EXEMPT)" for p in EXEMPT if not exists(p)]


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "src", "tests", "benches", "examples"],
                         capture_output=True, text=True, check=True).stdout.split()
    found = [p for p in out if p.endswith(".rs")]
    if not found:
        raise SystemExit("check_clippy_textlints: no tracked Rust file found; run it from the repository root")
    return found


def self_test() -> int:
    def fn(n, pre=""):
        return pre + "fn f() {\n" + "    let a = 1;\n" * (n - 1) + "}\n"
    cases = [
        ("101 body lines flagged", fn(102), 1),
        ("100 body lines fine", fn(101), 0),
        ("99 body lines fine", fn(100), 0),
        ("allow on the fn honoured", fn(120, "#[allow(clippy::too_many_lines)]\n"), 0),
        ("file-level allow honoured", "#![allow(clippy::too_many_lines)]\n" + fn(120), 0),
        ("blank and comment lines not counted", "fn f() {\n" + "    // c\n\n" * 80 + "    let a = 1;\n" * 20 + "}\n", 0),
        ("braces in strings and comments do not end the fn", "fn f() {\n    let s = \"}\";\n    // }\n" + "    let a = 1;\n" * 101 + "}\n", 1),
        ("a tokio::test fn is skipped (the macro rewrites it)", "#[tokio::test(flavor = \"multi_thread\")]\nasync fn f() {\n" + "    let a = 1;\n" * 120 + "}\n", 0),
        ("a plain #[test] fn is checked", "#[test]\nfn f() {\n" + "    let a = 1;\n" * 120 + "}\n", 1),
        ("trait method without a body skipped", "trait T { fn f(&self); }\n", 0),
        ("push_str format flagged", 'fn f(s: &mut String) { s.push_str(&format!("{}", 1)); }\n', 1),
        ("+= &format flagged", 'fn f(s: &mut String) { *s += &format!("{}", 1); }\n', 1),
        ("a format in a comment or string is not flagged", 'fn f() { let _ = "push_str(&format!(x))"; } // s.push_str(&format!(y))\n', 0),
        ("a push_str(&format!) split over lines is flagged", 'fn f(s: &mut String) {\n    s.push_str(\n        &format!("{}", 1),\n    );\n}\n', 1),
        ("an allow inside a doc comment does not exempt the file", "/// #![allow(clippy::too_many_lines)]\n" + fn(120), 1),
        ("a same-line allow honoured", "#[allow(clippy::too_many_lines)] fn f() {\n" + "    let a = 1;\n" * 120 + "}\n", 0),
        ("a raw byte string with a brace does not end the fn", 'fn f() {\n    let s = br#"}"#;\n' + "    let a = 1;\n" * 101 + "}\n", 1),
        ("write! style fine", 'fn f(s: &mut String) { let _ = write!(s, "{}", 1); }\n', 0),
    ]
    stale = stale_exempt(lambda p: False)
    print(("ok   " if len(stale) == len(EXEMPT) else "FAIL ") + f"every exempt path that is gone is flagged: {len(stale)} of {len(EXEMPT)}")
    bad = 0 if len(stale) == len(EXEMPT) else 1
    for name, src, want in cases:
        got = len(check("t.rs", src))
        print(("ok   " if got == want else "FAIL ") + f"{name}: {got} finding(s), want {want}")
        bad += got != want
    print(f"check_clippy_textlints self-test: {bad} wrong")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    root = Path.cwd()
    paths = [p for a in argv for p in ([str(q) for q in sorted(Path(a).rglob("*.rs"))] if Path(a).is_dir() else [a])] \
        if argv else tracked(root)
    findings = ([] if argv else stale_exempt(lambda p: (root / p).exists())) + [f for p in paths if os.path.relpath(os.path.abspath(p), root) not in EXEMPT for f in check(p, Path(p).read_text(errors="replace"))]
    print("\n".join(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
