#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A test harness that pairs a TempDir with a child process must drop the child first.

Rust drops struct fields in declaration order. A struct that declares a `TempDir` above a `Child` (or `ChildGuard`)
removes the directory while the child may still be writing into it: `kill_on_drop` only sends the kill, it does not
wait. The child's late write (a config lock, a state file) then lands between `remove_dir_all` deleting the entries and
the final `rmdir`, which fails and is ignored, and the directory is left in TMPDIR, which fails the whole CI shard
(2026-11-12: tests/e2e_code_mode_journey.rs, `.gateway.yaml.lock`).

This scans every `struct Name { .. }` in tests/ and src/ for a TempDir field declared before a Child or ChildGuard
field and refuses it, naming the file, line, struct and both fields. `--self-test` runs the scanner on fixtures.
Standard library only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TEMPDIR = re.compile(r"\bTempDir\b")
CHILD = re.compile(r"\b(?:Child|ChildGuard)\b")
STRUCT = re.compile(r"\bstruct\s+(\w+)\s*(?:<[^{;]*>)?\s*(?:where[^{;]*)?\{")


def strip_comments(text: str) -> str:
    """Comments blanked (same length, so offsets and line numbers stay), string literals left alone."""
    out = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j:j + 2] == "/*": depth += 1; j += 2
                elif text[j:j + 2] == "*/": depth -= 1; j += 2
                else: j += 1
            out.append("".join(c if c == "\n" else " " for c in text[i:j])); i = j
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1]); i = j + 1
        else:
            out.append(text[i]); i += 1
    return "".join(out)


def fields(body: str, base: int, text: str) -> list[tuple[str, str, int]]:
    """(name, type, line) of each `name: Type` field of a struct body, split at commas outside <>, (), []."""
    result, depth, start = [], 0, 0
    for k, ch in enumerate(body + ","):
        if ch in "<([": depth += 1
        elif ch in ">)]": depth -= 1 if ch != ">" or body[k - 1:k] != "-" else 0
        elif ch == "," and depth == 0:
            piece = body[start:k]
            m = re.match(r"\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+)", piece, re.S)
            if m:
                result.append((m.group(1), m.group(2).strip(), text.count("\n", 0, base + start + m.start(1)) + 1))
            start = k + 1
    return result


def scan(text: str) -> list[tuple[int, str, str, str]]:
    """(line, struct, tempdir field, child field) for each struct with a TempDir declared above a Child."""
    clean = strip_comments(text)
    found = []
    for m in STRUCT.finditer(clean):
        depth, j = 1, m.end()
        while j < len(clean) and depth:
            depth += {"{": 1, "}": -1}.get(clean[j], 0); j += 1
        body = clean[m.end():j - 1]
        flds = fields(body, m.end(), clean)
        for ti, (tname, ttype, tline) in enumerate(flds):
            if not TEMPDIR.search(ttype):
                continue
            for cname, ctype, _ in flds[ti + 1:]:
                if CHILD.search(ctype):
                    found.append((tline, m.group(1), tname, cname)); break
    return found


def main() -> int:
    root = Path(".")
    bad = []
    for base in ("tests", "src"):
        for path in sorted((root / base).rglob("*.rs")):
            for line, struct, tname, cname in scan(path.read_text(errors="replace")):
                bad.append(f"{path}:{line}: struct {struct} declares {tname} (TempDir) before {cname} (a child process): "
                           f"the directory is removed first; declare the child above the TempDir and make its drop wait")
    for b in bad:
        print(f"::error::{b}")
    print(f"teardown order: {len(bad)} struct(s) drop a TempDir before a child process")
    return 1 if bad else 0


def self_test() -> int:
    cases = [
        ("a TempDir above a Child", "struct G {\n    _tmp: tempfile::TempDir,\n    child: tokio::process::Child,\n}\n", 1),
        ("a Child above the TempDir", "struct G {\n    child: tokio::process::Child,\n    _tmp: tempfile::TempDir,\n}\n", 0),
        ("a ChildGuard below a TempDir", "pub struct G {\n    pub dir: TempDir,\n    guard: ChildGuard,\n}\n", 1),
        ("an optional child below a TempDir", "struct G { tmp: TempDir, c: Option<Child>, port: u16 }\n", 1),
        ("no child at all", "struct G {\n    tmp: TempDir,\n    port: u16,\n}\n", 0),
        ("no TempDir at all", "struct G {\n    child: Child,\n}\n", 0),
        ("the TempDir between two children", "struct G { a: Child, t: TempDir, b: Child }\n", 1),
        ("a commented-out TempDir", "struct G {\n    // _tmp: TempDir,\n    child: Child,\n}\n", 0),
        ("generics and attributes", "pub(crate) struct G<T: Send> where T: Sync {\n    #[allow(dead_code)]\n    pub(crate) _t: TempDir,\n    kids: Vec<(String, Child)>,\n    x: T,\n}\n", 1),
        ("a type named Children is not a child", "struct G { t: TempDir, kids: Children }\n", 0),
        ("two structs, only the second is wrong", "struct A { c: Child, t: TempDir }\nstruct B { t: TempDir, c: Child }\n", 1),
    ]
    wrong = 0
    for label, source, want in cases:
        got = len(scan(source))
        ok = got == want
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: {got} found, want {want}")
    line = scan("\n\nstruct G {\n    _tmp: TempDir,\n    child: Child,\n}\n")
    ok = line == [(4, "G", "_tmp", "child")]
    wrong += not ok
    print(f"{'ok   ' if ok else 'WRONG'} the report names the TempDir field's line, the struct and both fields: {line}")
    print(f"self-test: {len(cases) + 1 - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
