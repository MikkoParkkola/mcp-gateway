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
field and refuses it, naming the file, line, struct and both fields. A struct that pairs a bare `Child` (which neither
kills nor waits when dropped) with a TempDir must also carry an `impl Drop for <Struct>` in the same file; a
`ChildGuard` or `gateway_bin::Reaped` is trusted to wait. Both are errors.

A function under tests/ that makes a temp dir and spawns a process (`.spawn()`) must also own or wait for the child:
`Reaped`, `StdioSession` (whose Drop waits), `ChildGuard`, `.stop(`/`.reap(`/`.wait(`/`.try_wait(`/`.kill().await`/`wait_with_output`
or an explicit `shutdown(`. Otherwise the temp dir can be removed while the live child still writes into it. Named and tuple structs are scanned; comments, string, raw-string and char literals are
blanked first; borrowed and `PhantomData` fields own nothing and are skipped. It fails if tests/ or src/ is missing or
holds no Rust file, so a wrong working directory cannot pass silently. `--self-test` runs the scanner on fixtures.

Known limits (a text scan, not a type checker): a TempDir or Child reached through a `use .. as` rename, a `type` alias or
a wrapper struct, enum struct-variants, and structs a macro generates from metavariables are not seen. Standard library only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TEMPDIR = re.compile(r"\bTempDir\b")
CHILD = re.compile(r"\b(?:Child|ChildGuard)\b")
STRUCT = re.compile(r"\bstruct\s+(\w+)\s*(?:<[^{;(]*>)?\s*(?:where[^{;]*)?([{(])")
BARE_CHILD = re.compile(r"\bChild\b")
NON_OWNING = re.compile(r"^\s*[&*]|PhantomData|\bfn\s*\(")
CHAR = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'\n])'")
RAW = re.compile(r"b?r(#*)\"")


def blank(lit: str, start: int, stop: int) -> str:
    """The literal with its contents (between start and stop) spaced out, newlines kept."""
    return lit[:start] + "".join(c if c == "\n" else " " for c in lit[start:stop]) + lit[stop:]


def strip_comments(text: str) -> str:
    """Comments and the contents of string, raw-string and char literals blanked (same length, so offsets and line
    numbers stay); a quote that opens a lifetime (`'a`) is not a char literal."""
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
        elif (m := RAW.match(text, i)) and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
            end = text.find('"' + m.group(1), m.end())
            j = n if end < 0 else end + 1 + len(m.group(1))
            out.append(blank(text[i:j], m.end() - i, j - i - len(m.group(1)) - 1)); i = j
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(blank(text[i:j + 1], 1, j - i)); i = j + 1
        elif (m := CHAR.match(text, i)):
            out.append("'" + " " * (m.end() - i - 2) + "'"); i = m.end()
        else:
            out.append(text[i]); i += 1
    return "".join(out)


def fields(body: str, base: int, text: str, named: bool = True) -> list[tuple[str, str, int]]:
    """(name, type, line) of each field of a struct body, split at commas outside <>, (), [] (a tuple struct's fields are
    named "0", "1", ..)."""
    result, depth, start = [], 0, 0
    for k, ch in enumerate(body + ","):
        if ch in "<([{": depth += 1
        elif ch in ">)]}": depth -= 1 if ch != ">" or body[k - 1:k] != "-" else 0
        elif ch == "," and depth == 0:
            piece = body[start:k]
            head = r"\s*(?:#\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?"
            m = re.match(head + r"(?:r#)?(\w+)\s*:\s*(.+)", piece, re.S) if named else re.match(head + r"()(.+)", piece, re.S)
            if m:
                name = m.group(1) if named else str(len(result))
                result.append((name, m.group(2).strip(), text.count("\n", 0, base + start + m.start(2)) + 1))
            start = k + 1
    return result


def scan(text: str) -> list[tuple[int, str, str, str]]:
    """(line, struct, tempdir field, child field) for each struct with a TempDir declared above a Child, or (child field
    empty) a bare Child beside a TempDir with no `impl Drop for <struct>` in the text."""
    clean = strip_comments(text)
    found = []
    for m in STRUCT.finditer(clean):
        open_, close = m.group(2), {"{": "}", "(": ")"}[m.group(2)]
        depth, j = 1, m.end()
        while j < len(clean) and depth:
            depth += {open_: 1, close: -1}.get(clean[j], 0); j += 1
        flds = [f for f in fields(clean[m.end():j - 1], m.end(), clean, open_ == "{") if not NON_OWNING.search(f[1])]
        tmp = [f for f in flds if TEMPDIR.search(f[1])]
        if not tmp:
            continue
        hit = False
        for ti, (tname, _, tline) in enumerate(flds):
            if not TEMPDIR.search(flds[ti][1]):
                continue
            for cname, ctype, _ in flds[ti + 1:]:
                if CHILD.search(ctype):
                    found.append((tline, m.group(1), tname, cname)); hit = True; break
            if hit:
                break
        has_drop = re.search(r"\bimpl\s+Drop\s+for\s+" + re.escape(m.group(1)) + r"\b", clean)
        if not hit and not has_drop and any(BARE_CHILD.search(f[1]) for f in flds):
            found.append((tmp[0][2], m.group(1), tmp[0][0], ""))
    return found


FN = re.compile(r"\bfn\s+(\w+)[^{;]*\{")
LOCAL_TMP = re.compile(r"\b(?:tempfile::)?tempdir(?:_in)?\s*\(|\bTempDir::new(?:_in)?\b|\.tempdir(?:_in)?\s*\(")
SPAWNS = re.compile(r"\.spawn\s*\(")
OWNS_CHILD = re.compile(r"\bReaped\b|\bStdioSession\b|\bChildGuard\b|\.stop\s*\(|\.reap(?:_within)?\s*\(|\.wait\s*\(|wait_with_output|\.try_wait\s*\(|\.kill\s*\(\s*\)\s*\.await|\bshutdown\s*\(")


def scan_locals(text: str) -> list[tuple[int, str]]:
    """(line, function) for each function that makes a temp dir and spawns a process but never owns or waits for it."""
    clean = strip_comments(text)
    found = []
    for m in FN.finditer(clean):
        depth, j = 1, m.end()
        while j < len(clean) and depth:
            depth += {"{": 1, "}": -1}.get(clean[j], 0); j += 1
        body = clean[m.end():j - 1]
        tmp = LOCAL_TMP.search(body)
        if tmp and SPAWNS.search(body) and not OWNS_CHILD.search(body):
            found.append((clean.count("\n", 0, m.end() + tmp.start()) + 1, m.group(1)))
    return found


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    bad, scanned = [], 0
    for base in ("tests", "src"):
        if not (root / base).is_dir():
            print(f"::error::teardown order: {root / base} is missing; nothing scanned")
            return 1
        for path in sorted((root / base).rglob("*.rs")):
            scanned += 1
            for line, struct, tname, cname in scan(path.read_text(errors="replace")):
                rel = path.relative_to(root)
                if cname:
                    bad.append(f"{rel}:{line}: struct {struct} declares {tname} (TempDir) before {cname} (a child process): "
                               f"the directory is removed first; declare the child above the TempDir and make its drop wait")
                else:
                    bad.append(f"{rel}:{line}: struct {struct} pairs {tname} (TempDir) with a bare Child but has no "
                               f"`impl Drop for {struct}`: a bare Child neither kills nor waits, so add a Drop that does, or use a guard")
    for path in sorted((root / "tests").rglob("*.rs")):
        for line, fn in scan_locals(path.read_text(errors="replace")):
            bad.append(f"{path.relative_to(root)}:{line}: fn {fn} makes a temp dir and spawns a process but never owns or waits for "
                       f"it (use gateway_bin::Reaped with Teardown::DrainThenRemove, or wait for the child before the dir goes)")
    if scanned == 0:
        print("::error::teardown order: no Rust file under tests/ or src/; nothing scanned")
        return 1
    for b in bad:
        print(f"::error::{b}")
    print(f"teardown order: {scanned} file(s), {len(bad)} problem(s) where a temp dir can be removed under a live child")
    return 1 if bad else 0


def self_test() -> int:
    cases = [
        ("a TempDir above a Child", "struct G {\n    _tmp: tempfile::TempDir,\n    child: tokio::process::Child,\n}\n", 1),
        ("a Child above the TempDir with a waiting Drop", "struct G {\n    child: tokio::process::Child,\n    _tmp: tempfile::TempDir,\n}\nimpl Drop for G { fn drop(&mut self) {} }\n", 0),
        ("a bare Child above the TempDir and no Drop", "struct G {\n    child: tokio::process::Child,\n    _tmp: tempfile::TempDir,\n}\n", 1),
        ("a Drop for another struct does not count", "struct G { c: Child, t: TempDir }\nstruct H { x: u8 }\nimpl Drop for H { fn drop(&mut self) {} }\n", 1),
        ("a ChildGuard above the TempDir needs no Drop", "struct G { g: ChildGuard, t: TempDir }\n", 0),
        ("a tuple struct, TempDir first", "struct G(TempDir, Child);\n", 1),
        ("a tuple struct, ChildGuard first", "pub struct G(pub ChildGuard, pub TempDir);\n", 0),
        ("braces inside a raw string do not hide the struct", 'const S: &str = r#"echo "x"#;\nstruct G { t: TempDir, c: Child }\nconst T: &str = "end";\n', 1),
        ("a char literal quote does not open a string", "fn f() { let q = '\"'; }\nstruct G { t: TempDir, c: Child }\n", 1),
        ("a lifetime tick is not a char literal", "struct G<'a> { t: TempDir, c: Child, r: &'a str }\n", 1),
        ("a struct named in a string is not a struct", 'const S: &str = "struct G { t: TempDir, c: Child }";\n', 0),
        ("borrowed fields own nothing", "struct G<'a> { t: &'a TempDir, c: &'a Child }\n", 0),
        ("PhantomData and fn pointers own nothing", "struct G { t: TempDir, p: PhantomData<Child>, f: fn(Child) }\n", 0),
        ("a nested-bracket attribute and a raw identifier", "struct G {\n    #[cfg_attr(x, doc = [1, 2])]\n    r#type: TempDir,\n    c: Child,\n}\n", 1),
        ("a ChildGuard below a TempDir", "pub struct G {\n    pub dir: TempDir,\n    guard: ChildGuard,\n}\n", 1),
        ("an optional child below a TempDir", "struct G { tmp: TempDir, c: Option<Child>, port: u16 }\n", 1),
        ("no child at all", "struct G {\n    tmp: TempDir,\n    port: u16,\n}\n", 0),
        ("no TempDir at all", "struct G {\n    child: Child,\n}\n", 0),
        ("the TempDir between two children", "struct G { a: Child, t: TempDir, b: Child }\n", 1),
        ("a commented-out TempDir", "struct G {\n    // _tmp: TempDir,\n    child: Child,\n}\n", 0),
        ("generics and attributes", "pub(crate) struct G<T: Send> where T: Sync {\n    #[allow(dead_code)]\n    pub(crate) _t: TempDir,\n    kids: Vec<(String, Child)>,\n    x: T,\n}\n", 1),
        ("a type named Children is not a child", "struct G { t: TempDir, kids: Children }\n", 0),
        ("two structs, both wrong", "struct A { c: Child, t: TempDir }\nstruct B { t: TempDir, c: Child }\n", 2),
        ("two structs, only the second is wrong", "struct A { c: Child, t: TempDir }\nimpl Drop for A { fn drop(&mut self) {} }\nstruct B { t: TempDir, c: Child }\n", 1),
    ]
    wrong = 0
    for label, source, want in cases:
        got = len(scan(source))
        ok = got == want
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: {got} found, want {want}")
    local = [
        ("a temp dir and a bare spawn", "fn t() {\n    let d = tempfile::tempdir().unwrap();\n    let c = cmd.spawn().unwrap();\n}\n", 1),
        ("a temp dir, a spawn and Reaped", "fn t() {\n    let d = tempdir().unwrap();\n    let c = Reaped::new(cmd.spawn().unwrap());\n}\n", 0),
        ("a temp dir, a spawn and a wait", "fn t() {\n    let d = tempdir().unwrap();\n    let mut c = cmd.spawn().unwrap();\n    c.wait().await;\n}\n", 0),
        ("a temp dir, a StdioSession", "fn t() {\n    let d = tempdir().unwrap();\n    let s = StdioSession::start(cmd).spawn();\n}\n", 0),
        ("a spawn but no temp dir", "fn t() {\n    let c = cmd.spawn().unwrap();\n}\n", 0),
        ("a temp dir but no spawn", "fn t() {\n    let d = tempdir().unwrap();\n    cmd.output();\n}\n", 0),
        ("a spawn named only in a comment", "fn t() {\n    let d = tempdir().unwrap();\n    // cmd.spawn() is elsewhere\n}\n", 0),
        ("two functions, one bare", "fn a() { let d = tempdir(); let c = x.spawn(); }\nfn b() { let d = tempdir(); let c = x.spawn(); c.wait(); }\n", 1),
        ("the line names the temp dir", "\n\nfn t() {\n    let d = tempdir().unwrap();\n    let c = x.spawn().unwrap();\n}\n", 1),
    ]
    for label, source, want in local:
        got = len(scan_locals(source))
        ok = got == want
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} local scan, {label}: {got} found, want {want}")
    line = scan("\n\nstruct G {\n    _tmp: TempDir,\n    child: Child,\n}\n")
    ok = line == [(4, "G", "_tmp", "child")]
    wrong += not ok
    print(f"{'ok   ' if ok else 'WRONG'} the report names the TempDir field's line, the struct and both fields: {line}")
    print(f"self-test: {len(cases) + len(local) + 1 - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
