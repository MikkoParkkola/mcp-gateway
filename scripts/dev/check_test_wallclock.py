#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A new sub-second real-time limit in a test file must say why a stall cannot flip the row.

A test that gives production code a short real-time limit it is not testing, or asserts "not yet expired" against the
real clock with no margin, turns red on a busy runner for a reason that has nothing to do with its subject. Rule: in
test code, a sub-second duration literal that is not a sleep STATEMENT carries a marker on its statement or the line
above it:

    // limit-under-test (<basis>): <reason, at least three words>

<basis> is fires-only (the row asserts only that the limit fires), paused-clock (tokio start_paused), injected-clock
(the test supplies the instant), absorbed-by: NAME (a named generous bound dominates it) or floor-raised: NAME
(production code raises the value; NAME is the function). Unmarked literals that already exist are frozen per file in
scripts/dev/test-wallclock-ceilings.tsv: a count above its ceiling fails, and so does a count below it ("lower it"),
so the list only ever tightens. With --base REV the list's total may not exceed REV's total, so a hand edit cannot
raise a ceiling.

Test code = *_tests.rs, */tests.rs, any /tests/ directory, tests/**, and any item under #[cfg(test)] in any .rs file.
Sub-second = from_millis(0<N<1000), from_micros(0<N<1e6), from_nanos(0<N<1e9), from_secs_f32/64(0<x<1), Duration::new(0, n).
Zero forms (ZERO, from_*(0)) mean "no delay", not a limit. Known blind spots: a net-zero swap (a harmless literal
replaced by a new limit in the same file) keeps the count; a limit built by arithmetic (from_secs(1) / 20) or passed in
through a variable defined elsewhere is not seen; a sleep-then-assert-positive flake is a different problem.

Usage: check_test_wallclock.py [--base REV] | --self-test | --bootstrap | --write-ceilings"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TSV = "scripts/dev/test-wallclock-ceilings.tsv"
MARK = re.compile(r"//\s*limit-under-test\s*\(([^)]*)\)\s*:\s*(.*)$")
BASES = {"fires-only", "paused-clock", "injected-clock"}
NAMED = {"absorbed-by", "floor-raised"}
NUM = r"(\d[\d_]*)(?:[iu](?:8|16|32|64|128|size))?"
LIT = re.compile(  # `,?`: rustfmt puts a trailing comma after an argument it wraps onto its own line
    rf"Duration::from_(millis|micros|nanos)\(\s*{NUM}\s*,?\s*\)"
    r"|Duration::from_secs_f(?:32|64)\(\s*(\d*\.\d+)(?:_?f(?:32|64))?\s*,?\s*\)"
    rf"|Duration::new\(\s*0(?:_?[iu](?:32|64))?\s*,\s*{NUM}\s*,?\s*\)"
)
LIMITS = {"millis": 1000, "micros": 1_000_000, "nanos": 1_000_000_000}


def mask(src: str) -> str:
    """Same length and newlines; comments turn into spaces, string and char contents into 'x'."""
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
            end = src.find('"' + rm.group(1), i + rm.end())
            j = n if end < 0 else end + 1 + len(rm.group(1))
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


def is_test_path(p: str) -> bool:
    return p.endswith(".rs") and (p.endswith("_tests.rs") or p.endswith("/tests.rs") or "/tests/" in p or p.startswith("tests/"))


def cfg_test_spans(m: str) -> list[tuple[int, int]]:
    """Offsets of each item under `#[cfg(test)]` (mod, fn, const, impl ...), found on the masked source."""
    spans = []
    for a in re.finditer(r"#\[\s*cfg\(\s*test\s*\)\s*\]", m):
        i = a.end()
        while True:  # more attributes on the same item
            b = re.compile(r"\s*#\[").match(m, i)
            if not b:
                break
            depth, i = 0, b.end() - 1
            while i < len(m):
                depth += m[i] == "["; depth -= m[i] == "]"; i += 1
                if depth == 0:
                    break
        j, depth = i, 0
        while j < len(m) and not (depth == 0 and m[j] in "{;"):
            depth += m[j] in "(["; depth -= m[j] in ")]"; j += 1
        if j < len(m) and m[j] == "{":
            depth = 0
            while j < len(m):
                depth += m[j] == "{"; depth -= m[j] == "}"; j += 1
                if depth == 0:
                    break
        spans.append((a.start(), min(j + 1, len(m))))
    return spans


def sub_second(match: re.Match) -> bool:
    unit, n, secs, n2 = match.group(1), match.group(2), match.group(3), match.group(4)
    if unit:
        return 0 < int(n.replace("_", "")) < LIMITS[unit]
    if secs is not None:
        return 0 < float(secs) < 1
    return 0 < int(n2.replace("_", "")) < 1_000_000_000


def in_sleep_statement(m: str, pos: int) -> bool:
    """True when the literal sits in the argument list of a `sleep(...)` call that is a whole statement
    (`sleep(..).await;` or `thread::sleep(..);`). A sleep used as an expression (a select! arm, a race) is a timeout."""
    depth, i = 0, pos - 1
    while i >= 0:
        ch = m[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                break
            depth -= 1
        elif ch in ";{}" and depth == 0:
            return False
        i -= 1
    if i < 0 or not re.search(r"\bsleep\s*$", m[:i]):
        return False
    depth, j = 0, i
    while j < len(m):
        depth += m[j] == "("; depth -= m[j] == ")"; j += 1
        if depth == 0:
            break
    if not re.match(r"\s*(\.await)?\s*;", m[j:]):
        return False
    before = m[:i].rstrip()  # the call must open the statement: only its path may come before it
    start = max(before.rfind(";"), before.rfind("{"), before.rfind("}")) + 1
    return re.fullmatch(r"\s*(\w+::)*sleep\s*", m[start:i]) is not None


def marker_problem(line: str) -> str | None:
    """None when `line` holds a valid marker, else the reason it is refused (the caller only passes marker lines)."""
    mt = MARK.search(line)
    basis, reason = mt.group(1).strip(), mt.group(2).strip()
    head, _, name = basis.partition(":")
    head, name = head.strip(), name.strip()
    if head in NAMED:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]*", name):
            return f"basis '{head}' must name the bound or function (e.g. {head}: NAME)"
    elif head not in BASES or name:
        return f"basis '{basis}' is not one of fires-only, paused-clock, injected-clock, absorbed-by: NAME, floor-raised: NAME"
    if len(reason.split()) < 3:
        return "the reason needs at least three words"
    return None


def check_text(path: str, text: str, force_test: bool = False) -> tuple[list[str], int]:
    """(findings, count of unmarked sub-second literals). Findings read `path:line: message`."""
    m = mask(text)
    lines = text.splitlines()
    spans = None if (force_test or is_test_path(path)) else cfg_test_spans(m)
    findings, unmarked = [], 0
    for ln_no, ln in enumerate(lines, 1):  # a malformed marker line is a finding of its own
        if MARK.search(ln):
            why = marker_problem(ln)
            if why:
                findings.append(f"{path}:{ln_no}: limit-under-test marker refused: {why}")
    for lit in LIT.finditer(m):
        if spans is not None and not any(a <= lit.start() < b for a, b in spans):
            continue
        if not sub_second(lit) or in_sleep_statement(m, lit.start()):
            continue
        ln_no = m.count("\n", 0, lit.start()) + 1
        before = m[: lit.start()]
        stmt_start = max(before.rfind(";"), before.rfind("{"), before.rfind("}")) + 1
        body = m[stmt_start:]
        first = m.count("\n", 0, stmt_start + len(body) - len(body.lstrip())) + 1  # first line of the statement
        # a marker on any line of the statement, or on the line above it
        cands = range(max(first - 1, 1), ln_no + 1)
        marked = any(MARK.search(lines[c - 1]) and marker_problem(lines[c - 1]) is None for c in cands if c <= len(lines))
        if not marked:
            unmarked += 1
            findings.append(f"{path}:{ln_no}: sub-second limit {lit.group(0)} in test code with no `// limit-under-test (<basis>): <reason>` marker")
    return findings, unmarked


def tracked_rs(root: Path) -> list[str]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "*.rs"], capture_output=True, text=True, check=True).stdout.split("\n")
    found = [p for p in out if p]
    if not found:
        raise SystemExit("check_test_wallclock: no tracked Rust file found; run it from the repository")
    return found


def scan(root: Path) -> tuple[list[str], dict[str, int]]:
    findings, counts = [], {}
    for p in tracked_rs(root):
        f, n = check_text(p, (root / p).read_text(errors="replace"))
        findings += f
        if n:
            counts[p] = n
    return findings, counts


def read_tsv(text: str) -> dict[str, int]:
    rows = {}
    for ln in text.splitlines():
        if ln.strip() and not ln.startswith("#"):
            path, _, n = ln.partition("\t")
            rows[path] = int(n)
    return rows


HEADER = ("# Unmarked sub-second real-time limits per test file: path<TAB>count.\n"
          "# A count above its row fails; a count below fails too (lower the row); a file with no row has ceiling 0.\n"
          "# Written by check_test_wallclock.py --bootstrap (once) and --write-ceilings (lowers only).\n")


def ceilings_problems(counts: dict[str, int], rows: dict[str, int], gone: set[str]) -> list[str]:
    out = []
    for p in sorted(set(counts) | set(rows)):
        n, cap = counts.get(p, 0), rows.get(p, 0)
        if p in gone and p in rows:
            out.append(f"{TSV}: row for {p} but the file is gone; delete the row")
        elif n > cap:
            out.append(f"{p}: {n} unmarked sub-second limits, ceiling {cap}: mark each new one with // limit-under-test (<basis>): <reason>")
        elif n < cap:
            out.append(f"{TSV}: {p} now has {n}, ceiling {cap}: lower it to {n} (check_test_wallclock.py --write-ceilings)")
    return out


def base_problem(base: str, rows: dict[str, int], root: Path) -> str | None:
    # Fail closed: a revision that does not resolve (a typo, an unexpanded placeholder) must not read as
    # "no list at the base yet", or the ratchet would pass without comparing anything.
    if subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
                      capture_output=True).returncode != 0:
        return f"--base {base} is not a commit in this repository; nothing was compared"
    if subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{base}:{TSV}"], capture_output=True).returncode:
        return None  # the commit exists and holds no list yet: nothing to compare against
    r = subprocess.run(["git", "-C", str(root), "show", f"{base}:{TSV}"], capture_output=True, text=True)
    if r.returncode != 0:
        return f"{TSV} at {base} exists but could not be read; nothing was compared"
    was = sum(read_tsv(r.stdout).values())
    if sum(rows.values()) > was:
        return f"{TSV}: total {sum(rows.values())} is above {base}'s {was}: a ceiling cannot be raised, mark the new limits instead"
    return None


def run(root: Path, base: str | None) -> int:
    findings, counts = scan(root)
    tsv = root / TSV
    rows = read_tsv(tsv.read_text()) if tsv.exists() else {}
    gone = {p for p in rows if not (root / p).exists()}
    # unmarked literals are judged by the count rule alone; marker refusals are findings of their own
    refusals = [f for f in findings if "marker refused" in f]
    # a file over its ceiling also lists each unmarked literal in it, so the author need not hunt for them
    over = {p for p, n in counts.items() if n > rows.get(p, 0)}
    detail = [f for f in findings if "no `//" in f and f.split(":", 1)[0] in over]
    probs = refusals + ceilings_problems(counts, rows, gone) + detail
    if base and (why := base_problem(base, rows, root)):
        probs.append(why)
    print("\n".join(probs))
    return 1 if probs else 0


def write_ceilings(root: Path, bootstrap: bool) -> int:
    _, counts = scan(root)
    tsv = root / TSV
    rows = read_tsv(tsv.read_text()) if tsv.exists() else {}
    if bootstrap:
        if rows:
            print("refused: --bootstrap only writes when the list has no rows yet", file=sys.stderr)
            return 2
        new = dict(counts)
    else:
        up = [p for p in counts if counts[p] > rows.get(p, 0)]
        if up:
            print("refused: --write-ceilings only lowers; mark these instead: " + ", ".join(sorted(up)), file=sys.stderr)
            return 2
        new = {p: n for p, n in counts.items() if n}
    tsv.write_text(HEADER + "".join(f"{p}\t{n}\n" for p, n in sorted(new.items())))
    print(f"wrote {len(new)} rows, total {sum(new.values())}")
    return 0


def self_test() -> int:
    ok = '// limit-under-test (fires-only): the row asserts only that the limit fires\n'
    sub = 'fn t() {\n    let d = Duration::from_millis(50);\n}\n'
    cases = [  # (label, path, text, expected unmarked count, expected substring in findings or "")
        ("a planted sub-second literal on a content row is refused", "src/a_tests.rs", sub, 1, "no `// limit-under-test"),
        ("the same with a valid marker above the statement passes", "src/a_tests.rs", 'fn t() {\n    ' + ok + '    let d = Duration::from_millis(50);\n}\n', 0, ""),
        ("a marker on the same line passes", "src/a_tests.rs", 'fn t() {\n    let d = Duration::from_millis(50); ' + ok.strip() + '\n}\n', 0, ""),
        ("a marker above a multi-line statement passes", "src/a_tests.rs", 'fn t() {\n    ' + ok + '    let r = call(\n        Duration::from_millis(50),\n    );\n}\n', 0, ""),
        ("a marker with no reason is refused", "src/a_tests.rs", '// limit-under-test (fires-only): short\nfn t() { let d = Duration::from_millis(50); }\n', 1, "at least three words"),
        ("an unlisted basis is refused", "src/a_tests.rs", '// limit-under-test (probably-fine): it is fine here ok\nfn t() { let d = Duration::from_millis(50); }\n', 1, "is not one of"),
        ("absorbed-by with no name is refused", "src/a_tests.rs", '// limit-under-test (absorbed-by): a bound covers it fully\nfn t() { let d = Duration::from_millis(50); }\n', 1, "must name"),
        ("floor-raised with no function name is refused", "src/a_tests.rs", '// limit-under-test (floor-raised): production raises this value\nfn t() { let d = Duration::from_millis(50); }\n', 1, "must name"),
        ("absorbed-by NAME passes", "src/a_tests.rs", '// limit-under-test (absorbed-by: HANG_BOUND): the wait is dominated by it\nfn t() { let d = Duration::from_millis(50); }\n', 0, ""),
        ("floor-raised NAME passes", "src/a_tests.rs", '// limit-under-test (floor-raised: effective_attempt_timeout): production raises it\nfn t() { let d = Duration::from_millis(1); }\n', 0, ""),
        ("paused-clock and injected-clock pass", "src/a_tests.rs", '// limit-under-test (paused-clock): virtual time never moves here\nfn a() { let d = Duration::from_millis(50); }\n// limit-under-test (injected-clock): the instant is supplied by the row\nfn b() { let d = Duration::from_millis(60); }\n', 0, ""),
        ("a sleep statement is exempt", "src/a_tests.rs", 'async fn t() {\n    tokio::time::sleep(Duration::from_millis(50)).await;\n    std::thread::sleep(Duration::from_millis(20));\n}\n', 0, ""),
        ("a rustfmt-wrapped sleep statement is exempt", "src/a_tests.rs", 'async fn t() {\n    tokio::time::sleep(\n        Duration::from_millis(50),\n    )\n    .await;\n}\n', 0, ""),
        ("a sleep as a select! arm is a timeout and is flagged", "src/a_tests.rs", 'async fn t() {\n    tokio::select! {\n        () = tokio::time::sleep(Duration::from_millis(20)) => {}\n    }\n}\n', 1, "sub-second limit"),
        ("a timeout plus a sleep on one line flags the timeout", "src/a_tests.rs", 'async fn t() {\n    let r = tokio::time::timeout(Duration::from_millis(50), f()).await; sleep(Duration::from_millis(5)).await;\n}\n', 1, "sub-second limit"),
        ("a literal in a non-test file is ignored", "src/a.rs", sub, 0, ""),
        ("an item under #[cfg(test)] in a production file is checked", "src/a.rs", '#[cfg(test)]\nfn helper() -> Duration { Duration::from_millis(50) }\n', 1, "sub-second limit"),
        ("an inline #[cfg(test)] mod is checked", "src/a.rs", 'fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let d = Duration::from_millis(50); }\n}\n', 1, "sub-second limit"),
        ("a cfg(test) mod in a production file leaves production code alone", "src/a.rs", '#[cfg(test)]\nmod tests { fn t() {} }\nfn prod() { let d = Duration::from_millis(50); }\n', 0, ""),
        ("from_secs_f64(0.5) and from_micros are caught", "src/a_tests.rs", 'fn t() { let a = Duration::from_secs_f64(0.5); let b = Duration::from_micros(500); }\n', 2, "sub-second limit"),
        ("Duration::new(0, n) is caught", "src/a_tests.rs", 'fn t() { let a = Duration::new(0, 500_000_000); }\n', 1, "sub-second limit"),
        ("1000 ms, 2 s, 2 s in micros and 5 s in nanos are not sub-second", "src/a_tests.rs", 'fn t() { let a = Duration::from_millis(1000); let b = Duration::from_secs(2); let c = Duration::from_micros(2_000_000); let d = Duration::from_nanos(5_000_000_000); }\n', 0, ""),
        ("zero forms are the no-delay value", "src/a_tests.rs", 'fn t() { let a = Duration::ZERO; let b = Duration::from_millis(0); let c = Duration::from_secs(0); }\n', 0, ""),
        ("a literal in a comment or a string is not counted", "src/a_tests.rs", 'fn t() {\n    // Duration::from_millis(50)\n    let s = "Duration::from_millis(50)";\n}\n', 0, ""),
        ("a typed literal with underscores is caught", "src/a_tests.rs", 'fn t() { let a = Duration::from_millis(5_0u64); }\n', 1, "sub-second limit"),
        ("a rustfmt-wrapped literal with a trailing comma is caught", "src/a_tests.rs", 'fn t() {\n    let d = Duration::from_millis(\n        50,\n    );\n}\n', 1, "sub-second limit"),
    ]
    bad = 0
    for label, path, text, want, needle in cases:
        f, n = check_text(path, text)
        good = n == want and (needle in "\n".join(f) if needle else True)
        if want == 0 and not needle:
            good = good and not [x for x in f if "no `//" in x]
        print(("ok   " if good else "FAIL ") + f"{label}: {n} unmarked, want {want}")
        bad += not good
    # ceilings
    probs = ceilings_problems({"a.rs": 3, "b.rs": 1}, {"a.rs": 2, "b.rs": 1, "c.rs": 1}, set())
    exp = [("a count above its ceiling fails", any("a.rs: 3 unmarked" in x for x in probs)),
           ("a count equal to its ceiling passes", not any("b.rs" in x for x in probs)),
           ("a count below its ceiling fails (lower it)", any("c.rs now has 0" in x for x in probs)),
           ("a new file with a literal and no row fails", any("new.rs" in x for x in ceilings_problems({"new.rs": 1}, {}, set()))),
           ("a row for a gone file fails", any("gone" in x for x in ceilings_problems({}, {"old.rs": 2}, {"old.rs"}))),
           ("a TSV round trip keeps the rows", read_tsv(HEADER + "a.rs\t2\nb.rs\t1\n") == {"a.rs": 2, "b.rs": 1}),
           ("a --base that is not a commit is refused, not skipped", base_problem("<MERGE_BASE>", {}, ROOT) is not None)]
    # The ratchet itself, against a throwaway repository whose base commit holds a list totalling 3.
    with tempfile.TemporaryDirectory() as d:
        git = ["git", "-C", d, "-c", "user.email=self-test@example.invalid", "-c", "user.name=self-test"]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "before the list"], check=True)
        before = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        (Path(d) / TSV).parent.mkdir(parents=True, exist_ok=True)
        (Path(d) / TSV).write_text(HEADER + "a.rs\t2\nb.rs\t1\n")
        subprocess.run(git + ["add", TSV], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "the list"], check=True)
        exp += [("a total raised above the base fails", base_problem("HEAD", {"a.rs": 3, "b.rs": 1}, Path(d)) is not None),
                ("a total equal to the base passes", base_problem("HEAD", {"a.rs": 2, "b.rs": 1}, Path(d)) is None),
                ("a base from before the list compares nothing", base_problem(before, {"a.rs": 9}, Path(d)) is None)]
    for label, good in exp:
        print(("ok   " if good else "FAIL ") + label)
        bad += not good
    print(f"check_test_wallclock self-test: {bad} wrong")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--bootstrap"]:
        return write_ceilings(ROOT, True)
    if argv[:1] == ["--write-ceilings"]:
        return write_ceilings(ROOT, False)
    base = argv[1] if argv[:1] == ["--base"] and len(argv) > 1 else None
    return run(ROOT, base)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
