#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No new private copy of the test-only cfg judgement (MIK-9387.TCFG.2).

Two readers decide whether code compiles only under test: cfg_is_test in
scripts/dev/check-orphan-test-modules.py and eval/test_only in
src/test_source_text.rs. Other code that decides it with its own match is a
copy, and copies drift: three of them disagreed on `any(test, unix)` and
`all(x, test)`.

Only operative idioms count, code that decides rather than text a row feeds
in: an escaped regex for `cfg(test`, the `("flag", "test")` tree form,
`is_ident("test")`, `contains_word(.., "test")`, and a `"#[cfg(test)]"`
literal compared or searched for, or bound to a const. Each match is keyed by
its file and qualified enclosing scope. The remaining copies are listed in
scripts/dev/cfg-reader-copies.txt with a count and a reason. The check fails
on a match the list does not cover, on a listed copy that is gone (lower its
count), and, with --base, on an allowance larger than the base's list (or,
when the base has no list yet, than the base tree's own matches): the list
only shrinks. ponytail: textual detectors; an idiom spelled another way
escapes them, an AST check is the upgrade if one does.
"""

from __future__ import annotations

import argparse
import ast
import collections
import io
import re
import subprocess
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIST = "scripts/dev/cfg-reader-copies.txt"
HEADER = "# path\tscope\tcount\treason\n"
EXEMPT = (
    "scripts/dev/check-orphan-test-modules.py",
    "src/test_source_text.rs",
    # The shared Rust reader's own pins, whose oracle is a deliberately
    # independent second evaluator.
    "src/test_source_text_tests.rs",
    "scripts/dev/check_cfg_reader_copies.py",
    "scripts/dev/test_check_cfg_reader_copies.py",
)
PY_IDIOMS = [
    re.compile(r"cfg\\+\(\s*(?:\(\?:)?(?:all\\+\()?\)?\??\s*test"),
    re.compile(r"""\(\s*["']flag["']\s*,\s*["']test["']\s*\)"""),
    re.compile(r"""(?:==|!=|startswith\()\s*["']#!?\[cfg\(test\)\]|["']#!?\[cfg\(test\)\]["']\s*(?:==|!=)"""),
]
RS_IDIOMS = [
    re.compile(r'is_ident\(\s*"test"\s*\)'),
    re.compile(r'contains_word\([^;]*"test"'),
    re.compile(
        r'(?:==|!=|starts_with\(|ends_with\(|contains\(|find\(|match_indices\(|strip_prefix\(|split\()'
        r'\s*"#!?\[cfg\(test\)\]'
    ),
    re.compile(r'const\s+\w+\s*:\s*&(?:\'static\s+)?str\s*=\s*"#!?\[cfg\(test\)\]"'),
    re.compile(r'"#!?\[cfg\(test\)\]"\s*(?:==|!=)'),
]
ITEM = re.compile(r"\b(?:fn|mod)\s+(?:r#)?(\w+)|\bimpl\b(?:<[^{]*?>)?\s+(?:[\w:<>, ]+\s+for\s+)?([\w:]+)")

Key = tuple[str, str]


def files(root: Path) -> list[tuple[str, str]]:
    out = []
    for top, ext in (("scripts", ".py"), ("src", ".rs"), ("tests", ".rs")):
        for path in sorted((root / top).rglob(f"*{ext}")):
            rel = path.relative_to(root).as_posix()
            if rel not in EXEMPT and "/.venv/" not in f"/{rel}":
                out.append((rel, path.read_text(encoding="utf-8", errors="replace")))
    return out


def py_scope(text: str):
    """Line -> qualified def/class scope."""
    scopes: dict[int, str] = {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return lambda line: "<module>"

    def walk(node, names):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = names + [child.name]
                for line in range(child.lineno, (child.end_lineno or child.lineno) + 1):
                    scopes[line] = ".".join(inner)
                walk(child, inner)
            else:
                walk(child, names)

    walk(tree, [])
    return lambda line: scopes.get(line, "<module>")


def rs_scope(text: str):
    """Offset -> qualified `mod`/`impl`/`fn` scope, by a brace scan over the
    text with string literals and line comments blanked."""
    code = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*', lambda m: " " * len(m.group(0)), text)
    spans, stack, pending = [], [], None
    for m in re.finditer(r"[{};]|" + ITEM.pattern, code):
        tok = m.group(0)
        if tok == "{":
            stack.append(pending)
            pending = None
            spans.append([m.start(), len(code), "::".join(n for n in stack if n)])
            spans[-1].append(len(stack))
        elif tok == "}":
            depth = len(stack)
            for span in reversed(spans):
                if span[3] == depth and span[1] == len(code):
                    span[1] = m.end()
                    break
            if stack:
                stack.pop()
        elif tok == ";":
            pending = None
        else:
            pending = m.group(1) or (m.group(2) or "").split("::")[-1]

    def scope(at: int) -> str:
        inside = [s for s in spans if s[0] < at < s[1]]
        return max(inside, key=lambda s: s[0])[2] if inside else "<module>"

    return lambda at: scope(at) or "<module>"


def py_code(text: str) -> str:
    """`text` with comments and docstrings blanked (newlines kept): prose, not code."""
    out = list(text)
    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))

    def chars(line_no, byte_col):
        # ast columns are UTF-8 byte offsets; the buffer is characters.
        return len(lines[line_no - 1].encode("utf-8")[:byte_col].decode("utf-8", "ignore"))

    def blank(sl, sc, el, ec):
        for i in range(starts[sl - 1] + sc, starts[el - 1] + ec):
            if out[i] != "\n":
                out[i] = " "

    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                blank(*tok.start, *tok.end)
        for node in ast.walk(ast.parse(text)):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
                doc = body[0].value
                if isinstance(doc, ast.Constant) and isinstance(doc.value, str):
                    blank(
                        doc.lineno, chars(doc.lineno, doc.col_offset),
                        doc.end_lineno, chars(doc.end_lineno, doc.end_col_offset),
                    )
    except (SyntaxError, tokenize.TokenError):
        pass
    return "".join(out)


# A lexer step: a raw string, a string, a char literal (kept), or a comment (blanked).
# A literal at the cursor: a raw string, a string (an escape may consume a
# newline), or a char literal. Literals are kept: an idiom can be one.
RS_LITERAL = re.compile(r"""(?:br|r)(?P<h>#*)"[\s\S]*?"(?P=h)|b?"(?:\\[\s\S]|[^"\\])*"|b?'(?:\\.|[^'\\\n])'""")


def rs_code(text: str) -> str:
    """`text` with `//` and `/* */` comments blanked (newlines kept), literals
    kept. Block comments nest, as in Rust, so `/* /* */ // */` ends at the
    outer `*/` and the code after it stays code."""
    out, i, n = [], 0, len(text)

    def blank(chunk: str) -> str:
        return "".join("\n" if c == "\n" else " " for c in chunk)

    while i < n:
        lit = RS_LITERAL.match(text, i) if text[i] in "\"'br" else None
        if lit and (text[i] in "\"'" or i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            out.append(lit.group(0))
            i = lit.end()
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(blank(text[i:end]))
            i = end
        elif text.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                    if depth == 0:
                        break
                else:
                    j += 1
            out.append(blank(text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def matches(rel: str, text: str) -> collections.Counter[Key]:
    found: collections.Counter[Key] = collections.Counter()
    # Scopes come from the original source (blanking a sole docstring would
    # leave a body that no longer parses); idioms are matched in the code.
    scope_text = text
    text = py_code(text) if rel.endswith(".py") else rs_code(text)
    if rel.endswith(".py"):
        scope = py_scope(scope_text)
        for idiom in PY_IDIOMS:
            for m in idiom.finditer(text):
                found[(rel, scope(text.count("\n", 0, m.start()) + 1))] += 1
    else:
        scope = rs_scope(text)
        for idiom in RS_IDIOMS:
            for m in idiom.finditer(text):
                found[(rel, scope(m.start()))] += 1
    return found


def parse_list(text: str) -> collections.Counter[Key]:
    listed: collections.Counter[Key] = collections.Counter()
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 4 or not cells[3].strip() or not cells[2].isdigit():
            raise ValueError(f"malformed allowance: {line!r}")
        key = (cells[0], cells[1])
        if key in listed:
            raise ValueError(f"listed twice: {cells[0]} {cells[1]}")
        listed[key] = int(cells[2])
    return listed


def found_in(root: Path) -> collections.Counter[Key]:
    total: collections.Counter[Key] = collections.Counter()
    for rel, text in files(root):
        total += matches(rel, text)
    return total


def problems(root: Path, base_list: str | None = None, base_found=None) -> list[str]:
    listed = parse_list((root / LIST).read_text(encoding="utf-8"))
    found = found_in(root)
    out = []
    for key in sorted(set(found) | set(listed)):
        rel, scope = key
        if found[key] > listed[key]:
            out.append(f"new copy: {rel} {scope} ({found[key]}, listed {listed[key]})")
        elif found[key] < listed[key]:
            out.append(f"stale allowance: {rel} {scope} (listed {listed[key]}, found {found[key]})")
    if base_list is not None or base_found is not None:
        base = parse_list(base_list) if base_list is not None else base_found
        for key in sorted(listed):
            if listed[key] > base[key]:
                out.append(f"allowance grew: {key[0]} {key[1]} (base {base[key]}, now {listed[key]})")
    return out


def git(*args: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def base_allowances(rev: str) -> tuple[str | None, collections.Counter[Key] | None]:
    """The base's list, or, when the base has none yet, its tree's matches."""
    # The given revision itself, not a merge-base: a list the base already
    # shrank may not regrow, whatever the branch's own history holds.
    commit = git("rev-parse", "--verify", f"{rev}^{{commit}}").strip()
    if LIST in git("ls-tree", "-r", "--name-only", commit, "--", LIST).split():
        return git("show", f"{commit}:{LIST}"), None
    found: collections.Counter[Key] = collections.Counter()
    for rel in git("ls-tree", "-r", "--name-only", commit, "--", "scripts", "src", "tests").split():
        wanted = rel.endswith(".py") if rel.startswith("scripts/") else rel.endswith(".rs")
        if wanted and rel not in EXEMPT and "/.venv/" not in f"/{rel}":
            found += matches(rel, git("show", f"{commit}:{rel}"))
    return None, found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", help="refuse an allowance larger than this revision's")
    args = ap.parse_args(argv)
    try:
        base_list, base_found = base_allowances(args.base) if args.base else (None, None)
        found = problems(ROOT, base_list, base_found)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"cfg reader copies: {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(f"FAIL {line}")
    if found:
        print("Judge test-only code with cfg_is_test (Python) or test_source_text::test_only (Rust).")
        return 1
    print("cfg reader copies: none outside the shared readers and the listed allowances")
    return 0


if __name__ == "__main__":
    sys.exit(main())
