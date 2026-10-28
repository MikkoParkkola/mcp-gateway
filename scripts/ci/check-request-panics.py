#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8691.PANIC.3: a new
unwrap/expect/panic-family site in non-test, non-operator product code fails CI unless it carries an
`// invariant:` comment. Existing sites are listed in a shrink-only baseline the scanner writes.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE_REL = Path("scripts/ci/request-panic-baseline.txt")

OPERATOR_PREFIXES = (
    "src/commands/",
    "src/cli/",
    "src/main",
    "src/kubernetes",
    "src/debug_trust_roots",
    "src/win_acl/",
    "src/validator/report.rs",
    "src/validator/fix.rs",
    "src/validator/cli_handler.rs",
    "src/trust/lab",
    "src/honest_task_tokens",
)

_CFG_RE = re.compile(r"#\s*\[\s*cfg\s*\(")
_RE_UNWRAP = re.compile(r"\.\s*unwrap\s*\(\s*\)")
_RE_EXPECT = re.compile(r"\.\s*expect\s*\(")
# Any path call, whatever precedes the last `::` (nested generics, a const
# block, a qualified `<T>::` path, an alias): match on the suffix alone.
_RE_PATH = re.compile(r"::\s*(?:r#)?(?:unwrap|expect)\s*\(")
_RE_RAW_UNWRAP = re.compile(r"\.\s*r#unwrap\s*\(\s*\)")
_RE_RAW_EXPECT = re.compile(r"\.\s*r#expect\s*\(")
_RE_MACRO = re.compile(r"\b(?:panic|unreachable|unimplemented|todo)\s*!")

_FN_ITEMS = {"fn", "struct", "enum", "union", "impl", "mod", "trait"}
_LET_ITEMS = {"let", "const", "static", "type", "use"}
_PREFIX_WORDS = {"async", "const", "unsafe"}

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _load_orphan():
    path = ROOT / "scripts/dev/check-orphan-test-modules.py"
    spec = importlib.util.spec_from_file_location("check_orphan_test_modules", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ORPHAN = _load_orphan()


def _normalize(line: str) -> str:
    return " ".join(line.split())


def _is_operator(rel_posix: str) -> bool:
    return any(rel_posix.startswith(p) for p in OPERATOR_PREFIXES)


def _rs_files_for_root(root: Path, orphan):
    try:
        if root.resolve() == ROOT.resolve():
            return orphan.src_sources()
    except OSError:
        pass
    skip = getattr(orphan, "SKIP_DIRS", {".git", "target", "node_modules"})
    src = root / "src"
    if not src.is_dir():
        return []
    out = []
    for p in src.rglob("*.rs"):
        try:
            parts = p.relative_to(root).parts
        except ValueError:
            continue
        if skip.intersection(parts):
            continue
        out.append(p)
    return sorted(out)


def read_baseline_counts(path: Path) -> dict[tuple[str, str], int]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise SystemExit(f"no baseline at {BASELINE_REL.as_posix()}; run --write-baseline")
    return _parse_baseline(text, f"in {path}")


def _parse_baseline(text: str, where: str) -> dict[tuple[str, str], int]:
    # Strict: a line that is not exactly path, text, count fails, never skips.
    counts: dict[tuple[str, str], int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not parts[2].strip().isdigit():
            raise SystemExit(f"request-panics: malformed baseline line {number} {where}: {line!r}")
        counts[(parts[0], parts[1])] = int(parts[2].strip())
    return counts


def write_baseline_counts(path: Path, current: dict) -> None:
    items = []
    for (rel, norm), v in current.items():
        cnt = len(v) if isinstance(v, list) else int(v)
        items.append((rel, norm, cnt))
    items.sort()
    out = "".join(f"{rel}\t{norm}\t{cnt}\n" for rel, norm, cnt in items)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(out, encoding="utf-8")


def _skip_ws(code: str, i: int) -> int:
    n = len(code)
    while i < n and code[i].isspace():
        i += 1
    return i


def _read_ident(code: str, i: int):
    m = _IDENT_RE.match(code, i)
    if m:
        return m.group(0), m.end()
    return None, i


def _skip_attributes(code: str, i: int, orphan) -> int:
    n = len(code)
    while True:
        i = _skip_ws(code, i)
        if i < n and code[i] == "#":
            j = i + 1
            while j < n and code[j].isspace():
                j += 1
            if j < n and code[j] == "!":
                j += 1
                while j < n and code[j].isspace():
                    j += 1
            if j < n and code[j] == "[":
                i = orphan.attribute_end(code, j + 1)
                continue
        break
    return i


def _skip_pub(code: str, i: int) -> int:
    i = _skip_ws(code, i)
    word, wend = _read_ident(code, i)
    if word != "pub":
        return i
    i = _skip_ws(code, wend)
    if i < len(code) and code[i] == "(":
        depth = 0
        n = len(code)
        while i < n:
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
    return _skip_ws(code, i)


def _classify_item(code: str, attr_end: int, orphan):
    i = _skip_attributes(code, attr_end, orphan)
    i = _skip_pub(code, i)
    p1 = i
    j = p1
    while True:
        j = _skip_ws(code, j)
        word, wend = _read_ident(code, j)
        if word in _PREFIX_WORDS:
            j = wend
            continue
        if word == "extern":
            j = wend
            j = _skip_ws(code, j)
            if j < len(code) and code[j] == '"':
                k = j + 1
                while k < len(code) and code[k] != '"':
                    k += 1
                if k < len(code):
                    k += 1
                j = k
            continue
        break
    j = _skip_ws(code, j)
    word, _ = _read_ident(code, j)
    fn_like = word in _FN_ITEMS
    word1, _ = _read_ident(code, p1)
    let_like = (word1 in _LET_ITEMS) and not fn_like
    return fn_like, let_like


def _item_end(code: str, attr_end: int, fn_like: bool, let_like: bool) -> int:
    depth = 0
    k = attr_end
    n = len(code)
    while k < n:
        c = code[k]
        if c == "(" or c == "[" or c == "{":
            depth += 1
            k += 1
        elif c == ")" or c == "]" or c == "}":
            if depth == 0:
                return k
            if c == "}" and depth == 1:
                if let_like:
                    depth -= 1
                    k += 1
                    continue
                return k + 1
            depth -= 1
            k += 1
        elif c == ";" and depth == 0:
            return k + 1
        elif c == "," and depth == 0:
            if not fn_like:
                return k + 1
            k += 1
        else:
            k += 1
    return n


def _blank_cfg_items(code: str, orphan) -> str:
    matches = list(_CFG_RE.finditer(code))
    if not matches:
        return code
    descs = []
    for m in matches:
        expr = orphan.cfg_expression(code, m.end())
        if not (orphan.cfg_is_test(expr) or expr.strip() == "kani"):
            continue
        bracket = code.find("[", m.start(), m.end())
        if bracket < 0:
            continue
        try:
            attr_end = orphan.attribute_end(code, bracket + 1)
        except Exception:
            continue
        descs.append((m.start(), attr_end))
    descs.sort()
    if not descs:
        return code
    out = list(code)
    wiped: list[tuple[int, int]] = []

    def _inside(s: int) -> bool:
        for a, b in wiped:
            if a <= s < b:
                return True
        return False

    for start, attr_end in descs:
        if _inside(start):
            continue
        fn_like, let_like = _classify_item(code, attr_end, orphan)
        end = _item_end(code, attr_end, fn_like, let_like)
        if end <= start:
            continue
        for k in range(start, min(end, len(out))):
            if out[k] != "\n":
                out[k] = " "
        wiped.append((start, end))
    return "".join(out)


def _find_site_starts(blanked: str) -> list[int]:
    starts: list[int] = []
    for rx in (_RE_UNWRAP, _RE_EXPECT, _RE_PATH, _RE_RAW_UNWRAP, _RE_RAW_EXPECT, _RE_MACRO):
        for m in rx.finditer(blanked):
            starts.append(m.start())
    return sorted(set(starts))


def _line_comment_starts(text: str) -> set[int]:
    """Offsets of every `//` that opens a real line comment in `text`.

    One pass over the whole file, so a string or block comment that spans
    lines is tracked across them: a `// invariant:` inside a multiline
    literal never reads as a marker on a later line.
    """
    starts: set[int] = set()
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        boundary = not (i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_"))
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            starts.add(i)
            j = text.find("\n", i)
            if j < 0:
                break
            i = j + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            i = j
            continue
        # Raw strings, with an optional byte or C prefix: r"", r#""#, br#""#, cr#""#.
        r = i + 1 if c in "bc" and i + 1 < n and text[i + 1] == "r" else i
        if boundary and text[r] == "r":
            k = r + 1
            while k < n and text[k] == "#":
                k += 1
            if k < n and text[k] == '"':
                closing = '"' + text[r + 1 : k]
                end = text.find(closing, k + 1)
                if end < 0:
                    break
                i = end + len(closing)
                continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c == "'":
            # Char literals only ('x', '\n', '\u{..}', '\x41'); a lifetime 'a
            # is left alone so it never swallows code.
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 3)
                i = n if j < 0 else j + 1
                continue
            if i + 2 < n and text[i + 2] == "'" and text[i + 1] not in "'\n":
                i += 3
                continue
        i += 1
    return starts


def _line_has_invariant(text: str, line_start: int, line_end: int, comments: set[int]) -> bool:
    return any(
        line_start <= c < line_end and "// invariant:" in text[c:line_end] for c in comments
    )


def _is_invariant_standalone(text: str, line_start: int, line_end: int, comments: set[int]) -> bool:
    line = text[line_start:line_end]
    pos = line_start + len(line) - len(line.lstrip())
    return pos in comments and text.startswith("// invariant:", pos)


def _is_exempt(
    text: str, offsets: list[int], comments: set[int], orig_lines: list[str], blanked_lines: list[str], idx0: int
) -> bool:
    def span(k: int) -> tuple[int, int]:
        return offsets[k], offsets[k] + len(orig_lines[k])

    if _line_has_invariant(text, *span(idx0), comments):
        return True
    i = idx0
    while i > 0:
        prev_orig = orig_lines[i - 1].strip()
        if prev_orig == "":
            break
        if prev_orig.startswith("//"):
            break
        if i - 1 < len(blanked_lines):
            prev_blank = blanked_lines[i - 1].strip()
        else:
            prev_blank = prev_orig
        if prev_blank == "":
            break
        if prev_blank.endswith(";") or prev_blank.endswith("{") or prev_blank.endswith("}"):
            break
        i -= 1
    if i > 0 and _is_invariant_standalone(text, *span(i - 1), comments):
        return True
    return False


def collect_current(root: Path, test_only: set[Path], orphan) -> tuple[dict, int, int]:
    current: dict[tuple[str, str], list[int]] = {}
    scanned = 0
    total = 0
    for path in _rs_files_for_root(Path(root), orphan):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if _is_operator(rel):
            continue
        try:
            resolved = path.resolve()
        except OSError as exc:
            raise SystemExit(f"request-panics: cannot read {rel}: {exc}")
        if resolved in test_only:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SystemExit(f"request-panics: cannot read {rel}: {exc}")
        scanned += 1
        blanked, _ = orphan.blank(text)
        final = _blank_cfg_items(blanked, orphan)
        starts = _find_site_starts(final)
        if not starts:
            continue
        orig_lines = text.split("\n")
        blanked_lines = final.split("\n")
        offsets = [0]
        for line in orig_lines[:-1]:
            offsets.append(offsets[-1] + len(line) + 1)
        comments = _line_comment_starts(text)
        for st in starts:
            line_no = final.count("\n", 0, st) + 1
            idx0 = line_no - 1
            if idx0 < 0 or idx0 >= len(orig_lines):
                continue
            norm = _normalize(orig_lines[idx0])
            if _is_exempt(text, offsets, comments, orig_lines, blanked_lines, idx0):
                continue
            current.setdefault((rel, norm), []).append(line_no)
            total += 1
    return current, scanned, total


def find_new_sites(current: dict, baseline: dict[tuple[str, str], int]) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for (rel, norm), lines in current.items():
        base = baseline.get((rel, norm), 0)
        if len(lines) > base:
            for ln in sorted(lines)[base:]:
                out.append((rel, ln, norm))
    out.sort(key=lambda t: (t[0], t[1]))
    return out


def find_stale_allowances(current: dict, baseline: dict[tuple[str, str], int]) -> list[tuple[str, str, int, int]]:
    out: list[tuple[str, str, int, int]] = []
    for (rel, norm), base_cnt in baseline.items():
        v = current.get((rel, norm))
        if v is None:
            live = 0
        elif isinstance(v, list):
            live = len(v)
        else:
            live = int(v)
        if base_cnt > live:
            out.append((rel, norm, base_cnt, live))
    out.sort(key=lambda t: (t[0], t[1]))
    return out


def shrink_failures(
    current: dict[tuple[str, str], int], base: dict[tuple[str, str], int] | None
) -> list[tuple[tuple[str, str], int, int | None]]:
    if base is None:
        return []
    fails = []
    for key, cur in current.items():
        b = base.get(key)
        if b is None or cur > b:
            fails.append((key, cur, b))
    return fails


def load_base_via_git(rev: str) -> dict[tuple[str, str], int] | None:
    # An unknown revision is an error, never "no baseline": a mistyped base or
    # a shallow clone missing it must not pass silently. Only a revision that
    # exists without the file (the PR that introduces it) returns None.
    known = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if known.returncode != 0:
        raise SystemExit(f"request-panics: base revision {rev!r} is not in this clone")
    proc = subprocess.run(
        ["git", "show", f"{rev}:scripts/ci/request-panic-baseline.txt"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        return None
    return _parse_baseline(proc.stdout, f"at {rev}")


def _write_temp_files(tmp_root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = tmp_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _scan_temp(
    files: dict[str, str],
    test_only_rels: tuple[str, ...] = (),
    baseline: dict[tuple[str, str], int] | None = None,
    orphan=None,
):
    if orphan is None:
        orphan = _ORPHAN
    if baseline is None:
        baseline = {}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_temp_files(root, files)
        test_only = {(root / rel).resolve() for rel in test_only_rels}
        current, scanned, total = collect_current(root, test_only, orphan)
        findings = find_new_sites(current, baseline)
        return findings, current, scanned, total


def run_self_test() -> int:
    orphan = _ORPHAN
    passed = 0

    def check(name: str, cond: bool, extra: str = ""):
        nonlocal passed
        if not cond:
            print(f"self-test FAIL: {name} {extra}".rstrip())
            raise SystemExit(1)
        passed += 1

    # ---- Flagged ----
    f, _, _, _ = _scan_temp({"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"})
    check("flag new .unwrap()", len(f) == 1 and f[0][1] == 2, repr(f))

    f, _, _, _ = _scan_temp({"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap(\n    )\n}\n"})
    check("flag .unwrap( newline )", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Option<i32>) -> i32 {\n    x.expect(\n        "boom",\n    )\n}\n'}
    )
    check("flag multiline .expect(", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    Option::unwrap(x)\n}\n"}
    )
    check("flag Option::unwrap", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Result<i32, String>) -> i32 {\n    Result::expect(x, "boom")\n}\n'}
    )
    check("flag Result::expect", len(f) == 1, repr(f))

    for macro, body in [
        ("panic", 'panic!("boom")'),
        ("unreachable", 'unreachable!("x")'),
        ("unimplemented", "unimplemented!()"),
        ("todo", 'todo!("x")'),
    ]:
        f, _, _, _ = _scan_temp({"src/foo.rs": f"fn f() {{\n    {body}\n}}\n"})
        check(f"flag {macro}!", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(y: Option<i32>) -> i32 {\n    y.unwrap()\n}\n"},
        baseline={("src/foo.rs", "x.unwrap()"): 1},
    )
    check("flag edited baseline text", len(f) == 1 and f[0][2] == "y.unwrap()", repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"
                "fn g(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"
            )
        },
        baseline={("src/foo.rs", "x.unwrap()"): 1},
    )
    check("flag identical copy (count rises)", len(f) == 1 and f[0][1] == 5, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(x: Option<i32>, y: Option<i32>) {\n"
                "    x.unwrap(); // invariant: x ok\n"
                "    y.unwrap();\n"
                "}\n"
            )
        }
    )
    check("flag site under trailing invariant", len(f) == 1 and f[0][1] == 3, repr(f))

    for label, cfg_fn in [
        ("const fn", "const fn gated() -> i32 {\n    None::<i32>.unwrap()\n}"),
        ("async fn", "async fn gated() {\n    None::<i32>.unwrap();\n}"),
        ("unsafe fn", "unsafe fn gated() {\n    None::<i32>.unwrap();\n}"),
    ]:
        f, _, _, _ = _scan_temp(
            {
                "src/foo.rs": (
                    f"#[cfg(test)]\n{cfg_fn}\n"
                    "fn live(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"
                )
            }
        )
        check(f"flag live unwrap after cfg(test) {label}", len(f) == 1 and "x.unwrap()" in f[0][2], repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f() {\n"
                '    let s = br#"a"b"#;\n'
                "    let x: Option<i32> = None;\n"
                "    x.unwrap();\n"
                "}\n"
            )
        }
    )
    check("flag live unwrap after raw byte string", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(#[cfg(test)] x: u32, y: Option<i32>) -> i32 {\n"
                "    y.unwrap()\n"
                "}\n"
            )
        }
    )
    check("flag body with cfg(test) first param", len(f) == 1 and f[0][1] == 2, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(y: Option<i32>, #[cfg(test)] x: u32) -> i32 {\n"
                "    y.unwrap()\n"
                "}\n"
            )
        }
    )
    check("flag body with cfg(test) last param", len(f) == 1 and f[0][1] == 2, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                '#[cfg(any(test, feature = "x"))]\n'
                "fn f(x: Option<i32>) -> i32 {\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("flag under cfg(any(test, ...))", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "#[cfg(not(test))]\n"
                "fn f(x: Option<i32>) -> i32 {\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("flag under cfg(not(test))", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "#[cfg(kani)]\n"
                "fn kani_only() {\n"
                "    None::<i32>.unwrap();\n"
                "}\n"
                "fn live(y: Option<i32>) -> i32 {\n"
                "    y.unwrap()\n"
                "}\n"
            )
        }
    )
    check("flag live unwrap after cfg(kani) item", len(f) == 1 and "y.unwrap()" in f[0][2], repr(f))

    # ---- Not flagged ----
    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap() // invariant: ok\n}\n"}
    )
    check("pass trailing invariant", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(x: Option<i32>) -> i32 {\n"
                "    // invariant: ok\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("pass invariant line above", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(x: Option<i32>) -> i32 {\n"
                "    // invariant: ok\n"
                "    x\n"
                "        .as_ref()\n"
                "        .unwrap()\n"
                "}\n"
            )
        }
    )
    check("pass invariant above split chain", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "fn f(x: Option<i32>) -> i32 {\n"
                "    // moved down\n"
                "    // another comment\n"
                "\n"
                "\n"
                "    x.unwrap()\n"
                "}\n"
            )
        },
        baseline={("src/foo.rs", "x.unwrap()"): 1},
    )
    check("pass baseline site moved", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n        x.unwrap()\n}\n"},
        baseline={("src/foo.rs", "x.unwrap()"): 1},
    )
    check("pass whitespace-only reformat", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f() {\n    let s = "unwrap()";\n    let t = ".unwrap()";\n}\n'}
    )
    check("pass unwrap in string", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f() {\n    // x.unwrap() in comment\n    /* y.expect(\"x\") */\n}\n"}
    )
    check("pass unwrap in comment", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "#[cfg(test)]\n"
                "mod t {\n"
                "    pub fn f(x: Option<i32>) -> i32 {\n"
                "        x.unwrap()\n"
                "    }\n"
                "}\n"
            )
        }
    )
    check("pass cfg(test) mod body", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "#[cfg(test)]\n"
                "fn f<T, U>(x: Option<T>) -> T {\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("pass cfg(test) fn<T, U> body", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                "#[cfg(kani)]\n"
                "fn f(x: Option<i32>) -> i32 {\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("pass cfg(kani) body", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": (
                '#[cfg(all(feature = "x", test))]\n'
                "fn f(x: Option<i32>) -> i32 {\n"
                "    x.unwrap()\n"
                "}\n"
            )
        }
    )
    check("pass cfg(all(feature, test))", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/mytest.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"},
        test_only_rels=("src/mytest.rs",),
    )
    check("pass test_only_files member", len(f) == 0, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/cli/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"}
    )
    check("pass operator-module file", len(f) == 0, repr(f))

    # ---- Shrink-only ----
    check(
        "shrink fails on added key",
        len(shrink_failures({("a", "x"): 1, ("a", "y"): 1}, {("a", "x"): 1})) == 1,
    )
    check(
        "shrink fails on raised count",
        len(shrink_failures({("a", "x"): 2}, {("a", "x"): 1})) == 1,
    )
    check(
        "shrink passes on removed key",
        shrink_failures({("a", "x"): 1}, {("a", "x"): 1, ("a", "y"): 1}) == [],
    )
    check(
        "shrink passes on lowered count",
        shrink_failures({("a", "x"): 1}, {("a", "x"): 2}) == [],
    )
    check("shrink passes when base has no baseline", shrink_failures({("a", "x"): 1}, None) == [])

    # ---- Round trip ----
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_temp_files(
            root,
            {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"},
        )
        cur, _, _ = collect_current(root, set(), orphan)
        base = {k: len(v) for k, v in cur.items()}
        check("round trip temp baseline gives zero findings", find_new_sites(cur, base) == [])

    cur, _, _ = collect_current(ROOT, orphan.test_only_files(), orphan)
    rels = {rel for rel, _ in cur.keys()}
    check("round trip tip contains secrets.rs", "src/secrets.rs" in rels, repr(sorted(rels)[:5]))
    check("round trip tip contains config/secret_ref.rs", "src/config/secret_ref.rs" in rels)
    base = {k: len(v) for k, v in cur.items()}
    check("round trip tip baseline gives zero findings", find_new_sites(cur, base) == [])

    # ---- MIK-8691 round 1: path and raw-identifier calls ----
    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    Option::<i32>::unwrap(x)\n}\n"}
    )
    check("flag Option::<i32>::unwrap", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Maybe<i32>) -> i32 {\n    Maybe::unwrap(x)\n}\n"}
    )
    check("flag Maybe::unwrap via alias", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    x.r#unwrap()\n}\n"}
    )
    check("flag x.r#unwrap()", len(f) == 1, repr(f))

    # ---- MIK-8691 round 1: invariant marker must be a real line comment ----
    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Option<i32>) -> i32 {\n    x.unwrap(); let _s = "// invariant: x";\n}\n'}
    )
    check("not exempt: invariant in string on site line", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": "fn f(x: Option<i32>) -> i32 {\n    /* // invariant: */ x.unwrap()\n}\n"}
    )
    check("not exempt: invariant in block comment before site", len(f) == 1, repr(f))

    # ---- MIK-8691 round 2: path calls whatever precedes `::` ----
    for call in (
        "Option::<Vec<u8>>::unwrap(x)",
        "<Option<u8>>::unwrap(x)",
        "Option::r#unwrap(x)",
        "Foo::<{1 < 2}>::unwrap(x)",
        "Option::<i32>::expect(x, \"m\")",
    ):
        f, _, _, total = _scan_temp({"src/foo.rs": f"fn f() {{\n    let _a = {call};\n}}\n"})
        check(f"flag {call} once", len(f) == 1 and total == 1, repr(f))

    # ---- MIK-8691 round 2: the marker pass tracks literals across lines ----
    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Option<i32>) {\n    let _s = "a\n    // invariant: fake"; x.unwrap();\n}\n'}
    )
    check("not exempt: invariant inside a multiline string", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Option<i32>) {\n    /* a\n    // invariant: fake */ x.unwrap();\n}\n'}
    )
    check("not exempt: invariant inside a multiline block comment", len(f) == 1, repr(f))

    f, _, _, _ = _scan_temp(
        {
            "src/foo.rs": 'fn f(x: Option<i32>) {\n    let _s = cr#"a\n    // invariant: fake"#; x.unwrap();\n'
            "    // invariant: real\n    x.unwrap();\n}\n"
        }
    )
    check("multiline C raw string: only the real marker exempts", len(f) == 1, repr(f))

    # ---- MIK-8691 round 1: stale baseline allowances fail ----
    check(
        "stale: padded baseline fails",
        len(find_stale_allowances({("a", "x"): [2]}, {("a", "x"): 2})) == 1,
    )
    check(
        "stale: key with no live site fails",
        len(find_stale_allowances({}, {("a", "x"): 1})) == 1,
    )

    # ---- MIK-8691 round 1: strict working-tree baseline parse ----
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "baseline.txt"
        p.write_text("badline without tabs\n", encoding="utf-8")
        try:
            read_baseline_counts(p)
            check("malformed working baseline fails", False, "no error raised")
        except SystemExit as exc:
            msg = exc.code if isinstance(exc.code, str) else ""
            check("malformed working baseline fails", "malformed baseline line 1" in msg, repr(msg))

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "does-not-exist.txt"
        try:
            read_baseline_counts(p)
            check("missing committed baseline fails", False, "no error raised")
        except SystemExit as exc:
            msg = exc.code if isinstance(exc.code, str) else ""
            check("missing committed baseline fails", "no baseline at" in msg, repr(msg))

    # ---- MIK-8691 round 1: main() with a temp root ----
    with tempfile.TemporaryDirectory() as td:
        troot = Path(td)
        old_root = globals()["ROOT"]
        old_orphan_root = orphan.ROOT
        try:
            globals()["ROOT"] = troot
            orphan.ROOT = troot
            rc = main([])
            check("main empty scan returns 1", rc == 1, repr(rc))
        finally:
            globals()["ROOT"] = old_root
            orphan.ROOT = old_orphan_root

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td)
        (troot / "scripts/ci").mkdir(parents=True, exist_ok=True)
        (troot / "scripts/ci/request-panic-baseline.txt").write_text("", encoding="utf-8")
        try:
            subprocess.run(["git", "init"], cwd=str(troot), capture_output=True)
        except Exception:
            pass
        old_root = globals()["ROOT"]
        old_orphan_root = orphan.ROOT
        try:
            globals()["ROOT"] = troot
            orphan.ROOT = troot
            try:
                rc = main(["--base", "missing-rev-xyz-12345"])
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 1
            check("main missing base revision returns 1", rc == 1, repr(rc))
        finally:
            globals()["ROOT"] = old_root
            orphan.ROOT = old_orphan_root

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td)
        (troot / "scripts/ci").mkdir(parents=True, exist_ok=True)
        (troot / "scripts/ci/request-panic-baseline.txt").write_text("", encoding="utf-8")
        old_root = globals()["ROOT"]
        old_orphan_root = orphan.ROOT
        old_run = subprocess.run

        def _fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and len(cmd) >= 2 and cmd[0] == "git" and cmd[1] == "rev-parse":
                class _P:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                return _P()
            if isinstance(cmd, list) and len(cmd) >= 2 and cmd[0] == "git" and cmd[1] == "show":
                class _P:
                    returncode = 0
                    stdout = "badline without tabs\n"
                    stderr = ""

                return _P()
            return old_run(cmd, **kwargs)

        try:
            globals()["ROOT"] = troot
            orphan.ROOT = troot
            subprocess.run = _fake_run
            try:
                rc = main(["--base", "fakerev"])
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 1
            check("main malformed base line returns 1", rc == 1, repr(rc))
        finally:
            globals()["ROOT"] = old_root
            orphan.ROOT = old_orphan_root
            subprocess.run = old_run

    # ---- MIK-8691 round 2: C strings on the site's line never exempt it ----
    for lit in ('cr#" // invariant: "#', 'cr" // invariant: "', 'c" // invariant: "'):
        f, _, _, _ = _scan_temp({"src/foo.rs": f"fn f(x: Option<i32>) {{\n    x.unwrap(); let _s = {lit};\n}}\n"})
        check(f"not exempt: invariant in {lit}", len(f) == 1, repr(f))

    # ---- MIK-8691 round 2: a marker line inside a literal above a site ----
    f, _, _, _ = _scan_temp(
        {"src/foo.rs": 'fn f(x: Option<i32>) {\n    let _s = "\n// invariant: fake\n";\n    x.unwrap();\n}\n'}
    )
    check("not exempt: marker line inside a multiline string above", len(f) == 1, repr(f))
    f, _, _, _ = _scan_temp({"src/foo.rs": "fn f(x: Option<i32>) {\n    /*\n// invariant: fake\n    */\n    x.unwrap();\n}\n"})
    check("not exempt: marker line inside a block comment above", len(f) == 1, repr(f))

    # ---- MIK-8691 round 2: a C raw string with an inner quote hides nothing ----
    f, _, _, _ = _scan_temp({"src/foo.rs": 'fn f(x: Option<i32>) {\n    let _s = cr#"a"b"#;\n    x.unwrap();\n}\n'})
    check('site after cr#"a"b"# still flagged', len(f) == 1, repr(f))

    # ---- MIK-8691 round 2: the committed baseline is strict and live ----
    try:
        committed = read_baseline_counts(ROOT / BASELINE_REL)
        live, _, _ = collect_current(ROOT, _ORPHAN.test_only_files(), _ORPHAN)
        drift = find_new_sites(live, committed) + find_stale_allowances(live, committed)
        check("committed baseline parses and equals the live scan", bool(committed) and not drift, repr(drift[:3]))
    except SystemExit as exc:
        check("committed baseline parses and equals the live scan", False, repr(exc.code))

    # ---- MIK-8691 round 2: fail-closed paths through main() ----
    def _main_on(files: dict[str, str], baseline: str, link: str | None = None) -> int:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td)
            _write_temp_files(troot, {**files, BASELINE_REL.as_posix(): baseline})
            if link is not None:
                os.symlink(troot / "nowhere.rs", troot / link)
            old_root, old_orphan_root = globals()["ROOT"], orphan.ROOT
            try:
                globals()["ROOT"] = troot
                orphan.ROOT = troot
                return main([])
            finally:
                globals()["ROOT"] = old_root
                orphan.ROOT = old_orphan_root

    site = {"src/lib.rs": "fn f(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n"}
    key = "src/lib.rs\tx.unwrap()\t"
    rc = _main_on(site, key + "1\n")
    check("main exact baseline returns 0", rc == 0, repr(rc))
    rc = _main_on(site, key + "2\n")
    check("main padded baseline returns 1", rc == 1, repr(rc))
    rc = _main_on({"src/lib.rs": "fn f() {}\n"}, key + "1\n")
    check("main baseline key with no live site returns 1", rc == 1, repr(rc))
    rc = _main_on({"src/lib.rs": "mod gone;\n"}, "", link="src/gone.rs")
    check("main unreadable source returns 1", rc == 1, repr(rc))

    print(f"self-test: {passed} cases passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MIK-8691 request panic guard")
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--base", metavar="REV", default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if args.base is not None:
        try:
            current_path = ROOT / BASELINE_REL
            current = read_baseline_counts(current_path)
            base = load_base_via_git(args.base)
        except SystemExit as exc:
            if isinstance(exc.code, str):
                print(exc.code)
                return 1
            return exc.code if isinstance(exc.code, int) else 1
        if base is None:
            print(f"request-panics: no baseline at {args.base}, passing")
            return 0
        fails = shrink_failures(current, base)
        if fails:
            for (rel, norm), cur_cnt, base_cnt in sorted(fails, key=lambda t: (t[0][0], t[0][1])):
                print(f"baseline grew: {rel}\t{norm}\t{base_cnt}->{cur_cnt}")
            return 1
        print(f"request-panics: baseline shrink-only holds ({len(current)} keys)")
        return 0

    try:
        test_only = _ORPHAN.test_only_files()
        current, scanned, total = collect_current(ROOT, test_only, _ORPHAN)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code)
            return 1
        return exc.code if isinstance(exc.code, int) else 1
    # A scan that read nothing proves nothing: refuse it rather than pass.
    if scanned == 0:
        print("request-panics: no source files scanned; refusing to pass")
        return 1

    if args.write_baseline:
        out = ROOT / BASELINE_REL
        write_baseline_counts(out, current)
        print(f"request-panics: wrote {len(current)} keys to {BASELINE_REL.as_posix()}")
        return 0

    try:
        baseline = read_baseline_counts(ROOT / BASELINE_REL)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code)
            return 1
        return exc.code if isinstance(exc.code, int) else 1
    findings = find_new_sites(current, baseline)
    stale = find_stale_allowances(current, baseline)
    if findings or stale:
        for rel, line, norm in findings:
            print(f"{rel}:{line}: new panic site without // invariant: {norm}")
        for rel, norm, base_cnt, live in stale:
            print(f"stale baseline allowance: {rel} {norm} {base_cnt}->{live}; regenerate with --write-baseline")
        return 1
    print(f"request-panics: {scanned} files scanned, {total} non-exempt sites, 0 new")
    return 0


if __name__ == "__main__":
    sys.exit(main())
