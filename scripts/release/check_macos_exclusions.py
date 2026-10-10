#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every test that does not run on macOS is listed, with a reason (MIK-8174).

Usage: check_macos_exclusions.py [<root>]

Scans the tree's Rust files for a test function, or a module in a test file,
whose gate keeps it off macOS while not keeping it off Linux: the list is
macOS's coverage gap against Linux (MIK-8174). Each `#[cfg(..)]`,
`#![cfg(..)]` (item `*`) and `#[cfg_attr(.., ignore)]` is evaluated as a cfg
predicate (all, any, not, key = "value") under the macOS and the Linux CI
configuration with `--all-features` (MIK-8237): a feature is on when its
crate declares it, or as an optional dependency's implicit feature unless a
feature names that dependency through `dep:`. A multi-line attribute is read
whole. A predicate the reader cannot parse (a comment inside it) or cannot
decide (an unmodelled key) counts as kept off macOS, so it must be listed.
Also every `--skip` of the macOS job's test step in .github/workflows/ci.yml.
Fails on any such item missing from docs/release/macos-test-exclusions.tsv, on
a row with no reason, and on a row that no longer matches an item (a stale
exclusion). It guards against accidental omission, not adversarial spellings.

Stated limits: an untrusted multi-line attribute's item is the next item line
within 30 lines; a string spread over lines whose next line reads like
`fn name` can be taken for that item; stacked cfgs are judged one by one, so
gates off on both platforms only together still demand a row (over-listing)."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

LIST = "docs/release/macos-test-exclusions.tsv"
WORKFLOW = ".github/workflows/ci.yml"
# The two CI configurations a gate is evaluated under (MIK-8237), with every
# declared feature on (`--all-features`). A test counts as kept off macOS when
# its gate is off on macOS but not off on Linux: the list is macOS's coverage
# gap against Linux, so a Windows-only test is not in it. A key named here
# takes only its listed values; any other key is undecided.
MACOS = {
    "target_os": {"macos"},
    "target_vendor": {"apple"},
    "target_family": {"unix"},
    "target_arch": {"aarch64"},
    "target_pointer_width": {"64"},
    "target_endian": {"little"},
    "target_env": {""},
}
LINUX = {
    "target_os": {"linux"},
    "target_vendor": {"unk" + "nown"},
    "target_family": {"unix"},
    "target_arch": {"x86_64"},
    "target_pointer_width": {"64"},
    "target_endian": {"little"},
    "target_env": {"gnu"},
}
TRUE_FLAGS = {"test", "unix", "debug_assertions", "true"}
FALSE_FLAGS = {"windows", "false"}
UNDECIDED = None
ATTR = re.compile(r"#!?\[(cfg|cfg_attr)\(")
TOKEN = re.compile(r'\s*(?:(\w+)|("(?:[^"\\]|\\.)*")|([(),=]))')
TEST_ATTR = re.compile(r"#\[(tokio::)?test\b")
ITEM = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(fn|mod)\s+(\w+)")
TEST_CFG = re.compile(r"#\[cfg\((?:all\()?test\b")
TEST_FILE = re.compile(r"(^|/)tests?(/|\.rs$)|_tests?\.rs$|_tests/")


def tokens(text: str) -> list[str] | None:
    """`text` as identifiers, strings and punctuation; None on anything else
    (a comment, a path, a literal the grammar has no place for)."""
    out, at = [], 0
    while at < len(text):
        if not text[at:].strip():
            break
        match = TOKEN.match(text, at)
        if not match:
            return None
        out.append(match.group(0).strip())
        at = match.end()
    return out


def parse(toks: list[str], at: int = 0):
    """One predicate from `toks[at:]`: (tree, next index), or None.

    tree is ("all"|"any", [trees]), ("not", tree), ("flag", name) or
    ("pair", key, value)."""
    if at >= len(toks) or not re.fullmatch(r"\w+", toks[at]):
        return None
    name = toks[at]
    if name in ("all", "any", "not") and toks[at + 1 : at + 2] == ["("]:
        args, at = [], at + 2
        while toks[at : at + 1] != [")"]:
            parsed = parse(toks, at)
            if parsed is None:
                return None
            tree, at = parsed
            args.append(tree)
            if toks[at : at + 1] == [","]:
                at += 1
            elif toks[at : at + 1] != [")"]:
                return None
        if name == "not":
            return (("not", args[0]), at + 1) if len(args) == 1 else None
        return (name, args), at + 1
    if toks[at + 1 : at + 2] == ["="]:
        value = toks[at + 2] if at + 2 < len(toks) else ""
        if not value.startswith('"'):
            return None
        return ("pair", name, value[1:-1]), at + 3
    return ("flag", name), at + 1


def evaluate(tree, features: set[str], env: dict[str, set[str]]):
    """True, False or UNDECIDED, under `env` with `features` on."""
    kind = tree[0]
    if kind in ("all", "any"):
        values = [evaluate(t, features, env) for t in tree[1]]
        short = kind == "any"
        if short in values:
            return short
        return UNDECIDED if UNDECIDED in values else not short
    if kind == "not":
        value = evaluate(tree[1], features, env)
        return UNDECIDED if value is UNDECIDED else not value
    if kind == "flag":
        name = tree[1]
        return True if name in TRUE_FLAGS else False if name in FALSE_FLAGS else UNDECIDED
    _, key, value = tree
    if key == "feature":
        return value in features
    return value in env[key] if key in env else UNDECIDED


def split_top(text: str) -> list[str]:
    """`text` split at commas outside brackets and strings."""
    parts, depth, current, quoted = [], 0, "", False
    for i, ch in enumerate(text):
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            quoted = not quoted
        elif not quoted and ch in "([{":
            depth += 1
        elif not quoted and ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0 and not quoted:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    return parts


def attribute_span(line: str) -> tuple[str, str] | None:
    """The arguments of the attribute `line` starts with, and the trimmed text
    after its closing `)]`; None when it does not close as `)]`."""
    head = ATTR.match(line)
    depth, quoted = 1, False
    for i in range(head.end(), len(line)):
        ch = line[i]
        if ch == '"' and line[i - 1] != "\\":
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
            if depth == 0:
                if line[i + 1 : i + 2] != "]":
                    return None
                return line[head.end() : i], line[i + 2 :].strip()
    return None


def gated_on_test(attribute: str) -> bool:
    """Whether a `#[cfg(..)]` names `test` anywhere in its predicate (falling
    back to the leading-`test` spelling when it cannot be parsed)."""
    head = ATTR.match(attribute)
    if not head or head.group(1) != "cfg":
        return False
    span = attribute_span(attribute)
    tree = predicate(span[0]) if span else None
    if tree is None:
        return bool(re.search(r"\btest\b", unquoted(attribute)))

    def names_test(node) -> bool:
        if node[0] in ("all", "any"):
            return any(names_test(n) for n in node[1])
        if node[0] == "not":
            return False
        return node == ("flag", "test")

    return names_test(tree)


def predicate(text: str):
    """The parsed predicate in `text`, or None when it is not one whole predicate."""
    toks = tokens(text)
    if toks is None:
        return None
    parsed = parse(toks)
    if parsed is None or parsed[1] != len(toks):
        return None
    return parsed[0]


def off_macos(attribute: str, features: set[str]) -> bool:
    """Whether one whole `#[cfg(..)]` / `#![cfg(..)]` / `#[cfg_attr(..)]`
    keeps its item off macOS while not keeping it off Linux. An unparseable
    predicate counts (it must be listed), and so does one undecided on either
    side. `cfg_attr` counts only when it adds a top-level `ignore`."""
    head = ATTR.match(attribute)
    if not head:
        return False
    span = attribute_span(attribute)
    if span is None:
        return True
    body, rest = span
    # A trailing `// reason` is fine; any other text after the attribute is
    # not read, so the attribute counts.
    if rest and not rest.startswith("//"):
        return True
    if head.group(1) == "cfg":
        tree, runs_when = predicate(body), True
    else:
        parts = split_top(body)
        if len(parts) < 2:
            return True
        # A comment among the attributes may hide an `ignore`: it counts.
        if any("/*" in unquoted(part) or "//" in unquoted(part) for part in parts[1:]):
            return True
        if not any(re.fullmatch(r"ignore\b.*", part.strip(), re.S) for part in parts[1:]):
            return False
        tree, runs_when = predicate(parts[0]), False
    if tree is None:
        return True
    on_mac = evaluate(tree, features, MACOS)
    on_linux = evaluate(tree, features, LINUX)
    # cfg runs the item when true; cfg_attr(.., ignore) skips it when true.
    off_mac = on_mac is not runs_when
    off_linux = on_linux is (not runs_when)
    return off_mac and not off_linux


def crate_features(root: Path, file: Path, cache: dict[Path, set[str]]) -> set[str]:
    """The features `--all-features` turns on for the crate holding `file`:
    every `[features]` key, and each optional dependency no feature names
    through `dep:` (its implicit feature). No Cargo.toml: none."""
    for directory in [*file.parents]:
        manifest = directory / "Cargo.toml"
        if manifest.is_file():
            break
        if directory == root:
            return set()
    else:
        return set()
    if manifest not in cache:
        data = tomllib.loads(manifest.read_text())
        declared = set(data.get("features", {}))
        named = {v[4:] for values in data.get("features", {}).values() for v in values if v.startswith("dep:")}
        tables = [data, *data.get("target", {}).values()]
        optional = {
            name
            for scope in tables
            for table in ("dependencies", "dev-dependencies", "build-dependencies")
            for name, spec in scope.get(table, {}).items()
            if isinstance(spec, dict) and spec.get("optional")
        }
        cache[manifest] = declared | (optional - named)
    return cache[manifest]


def unquoted(text: str) -> str:
    """`text` with its string literals emptied."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def logical_lines(text: str) -> list[tuple[str, bool]]:
    """Trimmed lines, with an attribute spread over several lines joined into
    one: (text, whether it was joined)."""
    out: list[tuple[str, bool]] = []
    raw = [line.strip() for line in text.splitlines()]
    i = 0
    while i < len(raw):
        line = raw[i]
        depth = line.count("[") - line.count("]")
        if line.startswith(("#[", "#![")) and depth > 0:
            # The join never takes the next attribute or item: a bracket in a
            # comment or string can leave the count open, and it must not
            # swallow a test. The attribute is then read by bracket matching
            # that skips strings; left open, it does not close as `)]` and
            # counts.
            j = i
            while j + 1 < len(raw) and depth > 0:
                if raw[j + 1].startswith(("#[", "#![")) or ITEM.match(raw[j + 1]):
                    break
                j += 1
                depth += raw[j].count("[") - raw[j].count("]")
                line += " " + raw[j]
            out.append((line, True))
            i = j + 1
            continue
        out.append((line, False))
        i += 1
    return out


def excluded(root: Path) -> set[tuple[str, str]]:
    """(path, item) of every test function or test-file module kept off macOS."""
    found = set()
    features: dict[Path, set[str]] = {}
    for file in sorted(root.glob("**/*.rs")):
        rel = file.relative_to(root).as_posix()
        if rel.startswith("target/"):
            continue
        logical = logical_lines(file.read_text(errors="replace"))
        lines = [text for text, _ in logical]
        for n, (line, _joined) in enumerate(logical):
            if not ATTR.match(line):
                continue
            # A multi-line attribute is judged on its joined text. One whose
            # join a comment or a string spread over lines may have cut short
            # does not close as `)]`, and counts (fail closed); one holding a
            # comment does not parse, and counts.
            if not off_macos(line, crate_features(root, file, features)):
                continue
            if line.startswith("#!["):
                found.add((rel, "*"))
                continue
            # The attribute block this gate sits in, then the item it governs.
            start = n
            while start > 0 and lines[start - 1].startswith(("#[", "///", "//")):
                start -= 1
            end = n
            while end + 1 < len(lines) and lines[end + 1].startswith(("#[", "///", "//")):
                end += 1
            block = lines[start : end + 1]
            after = end + 1
            # Its item is then the next item line: the rest of an attribute
            # whose join ended early sits in between.
            # An attribute left unclosed counts, so its test must be found even
            # when the join ended early: its item is the next item line.
            unclosed = attribute_span(line) is None
            while unclosed and after < len(lines) and after <= end + 30 and not ITEM.match(lines[after]):
                if lines[after].startswith("#["):
                    block.append(lines[after])
                after += 1
            item = ITEM.match(lines[after]) if after < len(lines) else None
            if not item:
                continue
            kind, name = item.groups()
            # A module is a test module in a test file, or when its own gate
            # says `test` (`cfg(all(test, ...))` in a production mod.rs).
            test_gated = any(gated_on_test(a) for a in block)
            if (kind == "fn" and any(TEST_ATTR.match(a) for a in block)) or (
                kind == "mod" and (TEST_FILE.search(rel) or test_gated)
            ):
                found.add((rel, name))
    return found


def listed(root: Path) -> tuple[set[tuple[str, str]], list[str]]:
    rows, problems = set(), []
    for line in (root / LIST).read_text().splitlines()[1:]:
        cells = line.split("\t")
        if len(cells) < 4 or not cells[3].strip():
            problems.append(f"row without a reason: {line!r}")
            continue
        rows.add((cells[0], cells[1]))
    return rows, problems


def skipped(root: Path) -> set[tuple[str, str]]:
    """The `--skip` filters of the macOS job's test step, as (workflow, name)."""
    text = (root / WORKFLOW).read_text()
    job = text.split("\n  macos-check:\n", 1)[1]
    job = re.split(r"\n  [A-Za-z0-9_-]+:\n", job, maxsplit=1)[0]
    return {(WORKFLOW, name) for name in re.findall(r"--skip[= ](\S+)", job)}


def problems(root: Path) -> list[str]:
    rows, out = listed(root)
    items = excluded(root) | skipped(root)
    out += [f"not run on macOS and not listed: {p} {name}" for p, name in sorted(items - rows)]
    out += [f"stale row, nothing matches: {p} {name}" for p, name in sorted(rows - items)]
    return out


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    found = problems(root)
    for problem in found:
        print(problem)
    if found:
        print(f"Each test that does not run on macOS needs a row in {LIST}, with a reason.")
        return 1
    print("every test kept off macOS is listed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
