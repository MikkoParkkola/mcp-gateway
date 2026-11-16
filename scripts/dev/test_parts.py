#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The lib test split's codemod (`apply`) and checker (`check`).

The invariant: every test function compiles in exactly one part, through one `#[cfg(tpK)]` line on itself or on an
enclosing module, K being the table part of the directory of the file the tag sits in. The build script (scripts/dev/test-parts-build.rs) turns the variable
MCP_GATEWAY_TEST_PART into those cfgs; unset builds every part. Rows: scripts/dev/test_test_parts.py.
Run with the gates' environment (tree-sitter): scripts/gate-env/.venv/bin/python scripts/dev/test_parts.py check
"""

from __future__ import annotations

import functools
import importlib.util
import re
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
TABLE = Path("scripts/dev/test-parts.tsv")
SHARED = Path("scripts/dev/test-parts-shared.txt")
BUILD_RS = Path("scripts/dev/test-parts-build.rs")  # the package build script (Cargo.toml `build`)
CRATE_ALLOW = "#![cfg_attr(tp_partial, allow(unused, unfulfilled_lint_expectations))]"
CANDIDATE = re.compile(r"^(tests?|.*_tests?)$")
# Canonical tags only: tp1, tp12; never tp0 or tp01, which the build script never emits.
TAG = re.compile(r"^tp([1-9][0-9]*)$")
CONST_N = re.compile(r"\bconst\s+N\s*:\s*u32\s*=\s*([0-9]+)\s*;")
TAG_LINE = re.compile(r"^\s*#\[cfg\(tp([1-9][0-9]*)\)\]\s*$")
PART_NAME = re.compile(r"\btp\w*")


def _cfg_attr_applied(code: str) -> list[str]:
    """The attributes a `#[cfg_attr(pred, a, b)]` applies (`a`, `b`), split at top-level commas; the predicate, which
    may itself hold commas and `test`, is skipped."""
    inner = code[code.index("(") + 1 : code.rindex(")")]
    args, depth, start = [], 0, 0
    for i, ch in enumerate(inner):
        depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    args.append(inner[start:].strip())
    return args[1:]


def _attr_problems(rel: str, src: bytes, root) -> list[tuple[int, str, str]]:
    """(line, code, message) for every attribute that misuses a part cfg or makes a test through cfg_attr. Walks the
    tree's attribute nodes, so a predicate spread over lines is read whole and its owner is known: an exact tag may
    sit only on a module or a function (where the placement rules see it), `tp_partial` only in the crate-root
    allow, and any other cfg naming a part (a compound, a malformed tag such as tp01 or tpNone) is refused."""
    g = gate()
    out = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ("macro_definition", "macro_invocation"):
            # Attributes inside macro token trees are not parsed as attributes: read them as text (code review r2).
            code = g.blank(_text(src, node))[0]
            line = _line(src, node.start_byte)
            for attr in _attrs_in_text(code):
                flat = " ".join(attr.split())
                if re.match(r"#\s*!?\s*\[\s*cfg(?:_attr)?\s*\(", flat) and PART_NAME.search(flat):
                    out.append((line, "stray-cfg", "a part cfg inside a macro body is not supported"))
                if re.match(r"#\s*\[\s*cfg_attr\s*\(", flat) and _applies_test(flat):
                    out.append((line, "test-attr", "a test attribute applied through cfg_attr is not supported"))
            continue
        if node.type not in ("attribute_item", "inner_attribute_item"):
            stack.extend(node.children)
            continue
        path, _args = _attr_path_and_args(src, node)
        if path not in ("cfg", "cfg_attr"):
            continue
        code = " ".join(g.blank(_text(src, node))[0].split())
        line = _line(src, node.start_byte)
        if path == "cfg_attr" and _applies_test(code):
            out.append((line, "test-attr", "a test attribute applied through cfg_attr is not supported; write #[test]"))
        if not PART_NAME.search(code):
            continue
        if rel == "src/lib.rs" and node.type == "inner_attribute_item" and code == CRATE_ALLOW:
            continue
        owner = g._owner(node) if node.type == "attribute_item" else None
        if TAG_LINE.match(code) and _walked_item(owner):
            continue
        out.append((line, "stray-cfg", "a part cfg may only be an exact #[cfg(tpK)] line on a module or function"))
    return out


def _walked_item(owner) -> bool:
    """Whether `owner` is a module or function the walk records: at a file's top level or directly in a module's
    body, never in an impl, a trait or a function body (a tag there would never be placed or checked)."""
    if owner is None or owner.type not in ("mod_item", "function_item"):
        return False
    # Every enclosing scope up to the file must be a module body: one fn body, impl or block anywhere above hides it.
    up = owner.parent
    while up is not None and up.type != "source_file":
        if up.type != "declaration_list" or up.parent is None or up.parent.type != "mod_item":
            return False
        up = up.parent.parent
    return up is not None


def _applies_test(code: str) -> bool:
    """Whether a `#[cfg_attr(..)]` applies a test attribute, a leading `::` or a nested cfg_attr included."""
    for applied in _cfg_attr_applied(code):
        a = applied.lstrip(":").strip()
        if re.match(r"(?:tokio\s*::\s*)?test\b", a):
            return True
        if re.match(r"cfg_attr\s*\(", a) and _applies_test(f"#[{a}]"):
            return True
    return False


def _attrs_in_text(code: str):
    """Each `#[..]` / `#![..]` in `code` (comments and literals already blanked), by bracket matching."""
    for m in re.finditer(r"#\s*!?\s*\[", code):
        depth = 0
        for i in range(m.end() - 1, len(code)):
            depth += {"[": 1, "]": -1}.get(code[i], 0)
            if depth == 0:
                yield code[m.start() : i + 1]
                break
FIX = "scripts/gate-env/.venv/bin/python scripts/dev/test_parts.py apply"


class Finding(NamedTuple):
    code: str
    path: str
    line: int
    message: str


class Refusal(Exception):
    def __init__(self, findings: list[Finding]):
        super().__init__("; ".join(f"{f.path}:{f.line}: {f.code}: {f.message}" for f in findings))
        self.findings = findings


@functools.lru_cache(maxsize=1)
def gate():
    """scripts/dev/check-orphan-test-modules.py: the shared module resolver, cfg judgement and tree-sitter parser."""
    spec = importlib.util.spec_from_file_location("orphan_gate", HERE / "check-orphan-test-modules.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_n(root: Path) -> int | None:
    m = CONST_N.search((root / BUILD_RS).read_text(encoding="utf-8"))
    return int(m.group(1)) if m else None


def read_table(root: Path) -> list[tuple[str, int, int]]:
    """(directory, part, line number) per row; `#` lines are comments (the measured peaks)."""
    rows = []
    for no, line in enumerate((root / TABLE).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip() and not line.startswith("#"):
            directory, part = line.split("\t")[:2]
            rows.append((directory.strip().rstrip("/"), int(part), no))
    return rows


def read_shared(root: Path) -> list[tuple[str, int]]:
    """(full crate module path, line number) per entry."""
    return [
        (line.strip(), no)
        for no, line in enumerate((root / SHARED).read_text(encoding="utf-8").splitlines(), 1)
        if line.strip() and not line.startswith("#")
    ]


def table_part(rows: list[tuple[str, int, int]], directory: str) -> int | None:
    """The part of the nearest table row at or above `directory` (repo-relative, `/`-separated)."""
    parts = {d: p for d, p, _ in rows}
    d = directory
    while True:
        if d in parts:
            return parts[d]
        if "/" not in d:
            return None
        d = d.rsplit("/", 1)[0]


class Item(NamedTuple):
    """A module or function the walk found. Lines are 1-based."""

    kind: str  # "mod" or "fn"
    name: str
    path: tuple[str, ...]  # enclosing inline modules in this file, then the item's own name
    parent: int | None  # index of the enclosing module item in this file
    line: int  # the item's own first line (`mod` / `fn`), after its attributes
    first_attr_line: int  # the first attribute's line, or `line`
    tags: tuple[tuple[int, int, bool], ...]  # (part, line, shares its line with other code)
    test_cfg_line: int | None  # the line of a test-only `#[cfg(..)]`
    test_cfg_alone: bool  # nothing but whitespace precedes that attribute on its line
    is_test_fn: bool
    odd_test_attrs: tuple[str, ...]  # test-like attributes the walk does not support
    out_of_line: bool  # `mod name;`
    start: int  # byte extent, for the grammar-gap overlap
    end: int
    indent: str


class FileWalk(NamedTuple):
    items: list[Item]
    generators: set[str]  # macro_rules names whose body holds a test attribute
    macro_calls: dict[str, set[str]]  # macro_rules name -> macros its body calls (last path segment)
    invocations: list[tuple[str, int, int | None]]  # (macro name, line, enclosing module item) at item level
    errors: list[tuple[int, int]]  # error byte ranges
    parse_ok: bool
    attr_problems: list[tuple[int, str, str]]  # (line, code, message), from _attr_problems


TEST_ATTRS = ("test", "tokio::test")


def _text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _attr_path_and_args(src: bytes, attr_item) -> tuple[str, str]:
    inner = next((c for c in attr_item.named_children if c.type == "attribute"), None)
    if inner is None:
        return "", ""
    named = [c for c in inner.named_children if c.type not in ("line_comment", "block_comment")]
    path = "".join(_text(src, named[0]).split()) if named else ""
    args = _text(src, named[1]) if len(named) > 1 else ""
    return path, args


def _attributes(node) -> list:
    """The outer attributes of `node`, in source order, skipping comments between them."""
    found, prev = [], node.prev_named_sibling
    while prev is not None and prev.type in ("attribute_item", "line_comment", "block_comment"):
        if prev.type == "attribute_item":
            found.append(prev)
        prev = prev.prev_named_sibling
    return list(reversed(found))


def _line(src: bytes, byte: int) -> int:
    return src.count(b"\n", 0, byte) + 1


def _shares_line(src: bytes, node) -> bool:
    """Whether other code sits on the attribute's line, before or after it."""
    start = src.rfind(b"\n", 0, node.start_byte) + 1
    end = src.find(b"\n", node.end_byte)
    end = len(src) if end < 0 else end
    return bool(src[start : node.start_byte].strip() or src[node.end_byte : end].strip())


def walk_file(rel: str, text: str) -> FileWalk:
    g = gate()
    src = text.encode("utf-8")
    root = g._rust_parser().parse(src).root_node
    errors = [(a, b) for _, _, a, b in g._errors(root, src)] if root.has_error else []
    parse_ok = not errors or g._error_signature(g._errors(root, src)) == g.KNOWN_GAPS.get(rel)
    items: list[Item] = []
    generators: set[str] = set()
    macro_calls: dict[str, set[str]] = {}
    invocations: list[tuple[str, int, int | None]] = []

    def visit(container, path: tuple[str, ...], parent: int | None) -> None:
        for node in container.named_children:
            if node.type == "expression_statement" and node.named_child_count == 1:
                node = node.named_children[0]  # an item-level `gen!(..);` parses as a statement around the call
            if node.type == "macro_definition":
                # Blanked, so a comment between a name and `!` hides nothing; unioned, so a same-named definition
                # elsewhere in the file adds to the edges instead of replacing them (code review r2).
                body = g.blank(_text(src, node))[0]
                name = node.child_by_field_name("name")
                if name is not None:
                    own = _text(src, name).removeprefix("r#")
                    called = {c.removeprefix("r#") for c in re.findall(r"(?:r#)?(\w+)\s*!", body)} - {"macro_rules"}
                    macro_calls.setdefault(own, set()).update(called)
                    if re.search(r"#\s*\[\s*(?:tokio\s*::\s*)?test\b", body):
                        generators.add(own)
                continue
            if node.type == "macro_invocation":
                macro = node.child_by_field_name("macro")
                if macro is not None:
                    last = "".join(_text(src, macro).split()).rsplit("::", 1)[-1]
                    invocations.append((last.removeprefix("r#"), _line(src, node.start_byte), parent))
                continue
            if node.type not in ("mod_item", "function_item"):
                continue
            attrs = _attributes(node)
            tags, test_cfg, odd, is_test, cfg_alone = [], None, [], False, False
            for a in attrs:
                apath, args = _attr_path_and_args(src, a)
                inner = args.strip()[1:-1].strip() if args.strip().startswith("(") else ""
                if apath == "cfg" and TAG.match(inner):
                    tags.append((int(TAG.match(inner).group(1)), _line(src, a.start_byte), _shares_line(src, a)))
                elif apath == "cfg" and g.cfg_is_test(inner):
                    test_cfg = _line(src, a.start_byte)
                    cfg_alone = not src[src.rfind(b"\n", 0, a.start_byte) + 1 : a.start_byte].strip()
                elif apath in TEST_ATTRS:
                    is_test = True
                elif "test" in apath.rsplit("::", 1)[-1]:
                    odd.append(apath)
            kind = "mod" if node.type == "mod_item" else "fn"
            name = _text(src, node.child_by_field_name("name")).removeprefix("r#")
            body = node.child_by_field_name("body")
            first = attrs[0] if attrs else node
            line_start = src.rfind(b"\n", 0, first.start_byte) + 1
            items.append(
                Item(
                    kind=kind,
                    name=name,
                    path=(*path, name),
                    parent=parent,
                    line=_line(src, node.start_byte),
                    first_attr_line=_line(src, first.start_byte),
                    tags=tuple(tags),
                    test_cfg_line=test_cfg,
                    test_cfg_alone=cfg_alone,
                    is_test_fn=kind == "fn" and is_test,
                    odd_test_attrs=tuple(odd) if kind == "fn" else (),
                    out_of_line=kind == "mod" and body is None,
                    start=first.start_byte,
                    end=node.end_byte,
                    indent=src[line_start : first.start_byte].decode("utf-8", "replace"),
                )
            )
            if kind == "mod" and body is not None:
                visit(body, (*path, name), len(items) - 1)

    visit(root, (), None)
    return FileWalk(items, generators, macro_calls, invocations, errors, parse_ok, _attr_problems(rel, src, root))


TEST_ATTR_TEXT = re.compile(r"(?:tokio\s*::\s*)?test\s*[\](]")


def token_inventory(rel: str, text: str) -> dict[tuple[str, ...], int]:
    """The second, independent read of a file: each module's path in the file (enclosing inline modules, then its
    name) and the count of test functions directly in it, `()` for the file's top level. A token scan over code with
    comments and literals blanked (the orphan gate's `blank` and `TOKEN`), outside macro bodies."""
    g = gate()
    code, _ = g.blank(text)
    macros = g.macro_spans(code)
    found: dict[tuple[str, ...], int] = {(): 0}
    stack: list[str | None] = []
    pos = 0
    while m := g.TOKEN.search(code, pos):
        pos = m.end()
        in_macro = any(s <= m.start() < e for s, e in macros)
        if m.group("cfg"):
            pos = g.attribute_end(code, code.index("[", m.start()) + 1)
        elif m.group("attr"):
            body = m.end()
            while body < len(code) and code[body].isspace():
                body += 1
            # A test inside a fn body or another non-module block is not a module-level test function.
            if not in_macro and None not in stack and TEST_ATTR_TEXT.match(code, body):
                here = tuple(stack)
                found[here] = found.get(here, 0) + 1
            pos = g.attribute_end(code, m.end())
        elif m.group("name"):
            if not in_macro and None not in stack:
                found.setdefault((*[n for n in stack], m.group("name")), 0)
            if m.group("end") == "{":
                stack.append(m.group("name") if not in_macro and None not in stack else None)
        elif m.group("open"):
            stack.append(None)
        elif m.group("close"):
            if stack:
                stack.pop()
    return found


def walk_inventory(walk: FileWalk) -> dict[tuple[str, ...], int]:
    found: dict[tuple[str, ...], int] = {(): 0}
    for it in walk.items:
        if it.kind == "mod":
            found.setdefault(it.path, 0)
        elif it.is_test_fn:
            here = it.path[:-1]
            found[here] = found.get(here, 0) + 1
    return found


class Node(NamedTuple):
    """One item in the crate: its file, its index in that file's walk, its parent node and its crate path."""

    rel: str
    item: Item
    parent: int | None  # index into Crate.nodes
    crate_path: tuple[str, ...]


class Crate(NamedTuple):
    nodes: list[Node]
    files: dict[str, FileWalk]
    texts: dict[str, str]
    remounts: list[tuple[str, tuple[str, ...]]]  # (file, crate path) of a second mount of a walked file


def walk_crate(root: Path) -> Crate:
    """Every module and function reachable from src/lib.rs, through `mod x;` as the orphan gate resolves it."""
    g = gate()
    base = root.resolve()
    nodes: list[Node] = []
    files: dict[str, FileWalk] = {}
    texts: dict[str, str] = {}
    remounts: list[tuple[str, tuple[str, ...]]] = []
    # (file, owns its directory, parent node of the file's top level, crate path of the file's module)
    queue = [(base / "src" / "lib.rs", True, None, ())]
    while queue:
        path, owns_dir, parent, prefix = queue.pop(0)
        rel = path.relative_to(base).as_posix()
        if not path.is_file():
            continue
        if rel in files:
            remounts.append((rel, prefix))
            continue
        texts[rel] = path.read_text(encoding="utf-8")
        walk = walk_file(rel, texts[rel])
        files[rel] = walk
        # Each `mod name;` resolves in source order: two declarations may share a name under exclusive cfgs
        # (`#[cfg(unix)] #[path = "store_unix.rs"] mod platform;` beside a windows one), so a name maps to a queue.
        targets: dict[tuple[str, ...], list] = {}
        for p, via, names in g.bindings(path, owns_dir):
            if p.is_file():
                targets.setdefault(names, []).append((p, via))
        local: dict[int, int] = {}  # item index in this file -> node index
        for ix, it in enumerate(walk.items):
            up = parent if it.parent is None else local[it.parent]
            local[ix] = len(nodes)
            nodes.append(Node(rel, it, up, (*prefix, *it.path)))
            if it.out_of_line and targets.get(it.path):
                child, via = targets[it.path].pop(0)
                queue.append((child, via, local[ix], (*prefix, *it.path)))
    return Crate(nodes, files, texts, remounts)


def _ancestors(crate: Crate, ix: int):
    up = crate.nodes[ix].parent
    while up is not None:
        yield up
        up = crate.nodes[up].parent


def plan(crate: Crate, rows, shared: set[tuple[str, ...]]) -> tuple[dict[int, int], set[int]]:
    """(node -> part for every tag the tree should carry, the container nodes).

    A test root (a test-only module with no test-only ancestor) named tests / *_tests is a unit; any other test root
    and every shared-list module is a container, in every part. A module declared directly in a container is a unit
    unless it is shared too. A test function with no unit above it carries its own tag. A tag's part is the table part
    of the directory of the file it sits in."""
    nodes = crate.nodes
    in_test = [False] * len(nodes)
    containers: set[int] = set()
    units: set[int] = set()
    for ix, n in enumerate(nodes):
        it = n.item
        if it.kind != "mod":
            continue
        test_root = it.test_cfg_line is not None and not any(in_test[a] for a in _ancestors(crate, ix))
        in_test[ix] = it.test_cfg_line is not None or any(in_test[a] for a in _ancestors(crate, ix))
        if n.crate_path in shared:
            containers.add(ix)
        elif test_root and CANDIDATE.match(it.name):
            units.add(ix)
        elif test_root:
            containers.add(ix)
        elif n.parent in containers:
            units.add(ix)
    tagged = set(units)
    for ix, n in enumerate(nodes):
        if n.item.is_test_fn and not any(a in units for a in _ancestors(crate, ix)):
            tagged.add(ix)
    desired = {}
    for ix in tagged:
        directory = nodes[ix].rel.rsplit("/", 1)[0]
        desired[ix] = table_part(rows, directory)
    return desired, containers


class Analysis(NamedTuple):
    crate: Crate
    desired: dict[int, int]
    containers: set[int]
    findings: list[Finding]


def analyse(root: Path) -> Analysis:
    rows = read_table(root)
    shared_rows = read_shared(root)
    shared = {tuple(p.split("::")) for p, _ in shared_rows}
    crate = walk_crate(root)
    desired, containers = plan(crate, rows, shared)
    out: list[Finding] = []
    nodes = crate.nodes

    def add(code: str, rel: str, line: int, message: str) -> None:
        out.append(Finding(code, rel, line, message))

    # One file read two ways: a silent drop by the parser would put its tests in every part.
    for rel, walk in crate.files.items():
        if not walk.parse_ok:
            add("parse", rel, 1, "the file does not parse and is not a listed grammar gap")
        for it in walk.items:
            if (it.kind == "mod" or it.is_test_fn) and any(it.start < b and a < it.end for a, b in walk.errors):
                add("parse", rel, it.line, f"{it.name} overlaps a grammar gap")
        if walk_inventory(walk) != token_inventory(rel, crate.texts[rel]):
            add("cross-check", rel, 1, "the tree walk and the token scan disagree on modules or test functions")
        for no, code, message in walk.attr_problems:
            add(code, rel, no, message)
    for rel, path in crate.remounts:
        add("double-mount", rel, 1, f"also mounted as {'::'.join(path)}; one file can carry one set of tags")
    if CRATE_ALLOW not in [line.strip() for line in crate.texts.get("src/lib.rs", "").splitlines()]:
        add("crate-allow", "src/lib.rs", 1, f"add the line: {CRATE_ALLOW}")

    first = {}
    for ix, n in enumerate(nodes):
        first.setdefault(n.rel, ix)
    tags = {ix: n.item.tags for ix, n in enumerate(nodes) if n.item.tags}
    for ix, t in tags.items():
        n = nodes[ix]
        for part, line, same in t:
            if same:
                add("same-line", n.rel, line, "a tag must be its own line")
        if ix not in desired:
            code = "shared-tagged" if ix in containers else "misplaced"
            add(code, n.rel, t[0][1], f"remove this tag ({FIX})")
        elif [p for p, _, _ in t] != [desired[ix]]:
            add("wrong-part", n.rel, t[0][1], f"expected #[cfg(tp{desired[ix]})] ({FIX})")
    for ix, n in enumerate(nodes):
        if ix in desired and ix not in tags:
            add("untagged", n.rel, n.item.first_attr_line, f"add #[cfg(tp{desired[ix]})] above line {n.item.first_attr_line} ({FIX})")
        it = n.item
        if it.kind == "fn" and it.odd_test_attrs:
            add("test-attr", n.rel, it.line, f"{', '.join(it.odd_test_attrs)} is not a supported test attribute")
        if it.is_test_fn and sum(len(tags.get(a, ())) for a in (ix, *_ancestors(crate, ix))) > 1:
            add("two-tags", n.rel, it.line, f"{it.name} sits under more than one part tag")
    generators = set().union(*(w.generators for w in crate.files.values())) if crate.files else set()
    calls: dict[str, set[str]] = {}
    for w in crate.files.values():
        for m, called in w.macro_calls.items():
            calls.setdefault(m, set()).update(called)
    # A macro that calls a generator generates tests too, however deep the chain (code review r1).
    while grown := {m for m, called in calls.items() if m not in generators and called & generators}:
        generators |= grown
    for rel, walk in crate.files.items():
        for name, line, parent in walk.invocations:
            if name not in generators:
                continue
            here = first[rel] + parent if parent is not None else (nodes[first[rel]].parent if rel in first else None)
            chain = [] if here is None else [here, *_ancestors(crate, here)]
            if not any(a in desired and nodes[a].item.kind == "mod" for a in chain):
                add("test-macro", rel, line, f"{name}! makes tests; invoke it only inside a tagged module")
    _check_table(root, rows, crate, desired, add)
    _check_package(root, add)
    by_path: dict[tuple[str, ...], list[int]] = {}
    for ix, n in enumerate(nodes):
        if n.item.kind == "mod":
            by_path.setdefault(n.crate_path, []).append(ix)
    first_seen: dict[str, int] = {}
    for p, no in shared_rows:
        if p in first_seen:
            add("shared-entry", SHARED.as_posix(), no, f"{p} is listed again (first on line {first_seen[p]})")
            continue
        first_seen[p] = no
        hits = by_path.get(tuple(p.split("::")), [])
        if len(hits) != 1:
            add("shared-entry", SHARED.as_posix(), no, f"{p} names {len(hits)} modules, not exactly one")
            continue
        chain = [hits[0], *_ancestors(crate, hits[0])]
        if not any(nodes[a].item.kind == "mod" and nodes[a].item.test_cfg_line for a in chain):
            add("shared-entry", SHARED.as_posix(), no, f"{p} is production code, in every part already")
        tagged = [a for a in chain[1:] if a in desired]
        if tagged:
            above = "::".join(nodes[tagged[0]].crate_path)
            add("shared-entry", SHARED.as_posix(), no, f"{p} sits under the tagged {above}; share {above} instead")
    return Analysis(crate, desired, containers, out)


def _check_package(root: Path, add) -> None:
    """Cargo builds and packages this build script: Cargo.toml's `[package] build` names it and `[package] include`
    holds it (without the include, the packaged crate has no build script and every tagged test is compiled out of
    package-tests). Parsed as TOML, so a key in another table or the path in `exclude` does not count."""
    want = BUILD_RS.as_posix()
    try:
        package = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8")).get("package", {})
    except tomllib.TOMLDecodeError as err:
        add("package", "Cargo.toml", 1, f"Cargo.toml does not parse: {err}")
        return
    if package.get("build") != want:
        add("package", "Cargo.toml", 1, f'[package] needs build = "{want}"')
    if want not in package.get("include", []):
        add("package", "Cargo.toml", 1, f'[package] include needs "{want}"')


def _check_table(root: Path, rows, crate: Crate, desired: dict[int, int], add) -> None:
    n = read_n(root)
    if n is None:
        add("table-range", BUILD_RS.as_posix(), 1, "the build script declares no `const N: u32`")
        return
    seen_dirs: dict[str, int] = {}
    for directory, part, no in rows:
        if directory in seen_dirs:
            add("table-dup", TABLE.as_posix(), no, f"{directory} is listed again (first on line {seen_dirs[directory]})")
        seen_dirs.setdefault(directory, no)
        if not 1 <= part <= n:
            add("table-range", TABLE.as_posix(), no, f"part {part} is outside 1..={n}")
    unit_dirs = {crate.nodes[ix].rel.rsplit("/", 1)[0] for ix in desired}
    for directory, part, no in rows:
        if directory not in unit_dirs:
            add("stale-row", TABLE.as_posix(), no, f"{directory} holds no unit")
    tests_in = {k: 0 for k in range(1, n + 1)}
    units_in = {k: 0 for k in range(1, n + 1)}
    for ix, part in desired.items():
        if part in units_in:
            units_in[part] += 1
    for ix, node in enumerate(crate.nodes):
        if node.item.is_test_fn:
            for a in (ix, *_ancestors(crate, ix)):
                if a in desired:
                    if desired[a] in tests_in:
                        tests_in[desired[a]] += 1
                    break
    for k in range(1, n + 1):
        if not units_in[k] or not tests_in[k]:
            add("empty-part", TABLE.as_posix(), 1, f"part {k} has {units_in[k]} units and {tests_in[k]} tests")


def check(root: Path) -> list[Finding]:
    return analyse(root).findings


BLOCKS_APPLY = ("parse", "cross-check", "same-line")


def apply(root: Path) -> list[str]:
    """Bring every tag to the planned set; returns the files changed. Every edit is computed and validated before any
    file is written, so a refusal leaves the tree as it was. Only a line that is exactly a tag is deleted or
    rewritten; tags go in as their own line."""
    a = analyse(root)
    stop = [f for f in a.findings if f.code in BLOCKS_APPLY]
    nodes = a.crate.nodes
    for ix, part in a.desired.items():
        if part is None:
            stop.append(Finding("table-range", nodes[ix].rel, nodes[ix].item.line, "no table row covers this directory"))
    if stop:
        raise Refusal(stop)
    edits: dict[str, list[tuple[int, int, str | None]]] = {}  # rel -> (line, order, new text or None to delete)
    for ix, n in enumerate(nodes):
        lines = a.crate.texts[n.rel].split("\n")
        have = [line for _, line, _ in n.item.tags]
        want = a.desired.get(ix)
        for k, line in enumerate(have):
            if not TAG_LINE.match(lines[line - 1]):
                raise Refusal([Finding("same-line", n.rel, line, "a tag must be its own line")])
            keep = want is not None and k == 0
            text = TAG_LINE.sub(lambda m: m.group(0).replace(f"tp{m.group(1)}", f"tp{want}"), lines[line - 1]) if keep else None
            if text != lines[line - 1]:
                edits.setdefault(n.rel, []).append((line, 0, text))
        if want is not None and not have:
            if n.item.kind == "mod" and n.item.test_cfg_line:
                at = n.item.test_cfg_line
                alone = n.item.test_cfg_alone
            else:
                at = n.item.first_attr_line
                alone = not n.item.indent.strip()
            if not alone:
                # A tag line inserted above code that shares the item's line would gate that code instead.
                raise Refusal([Finding("same-line", n.rel, at, f"put {n.item.name} on its own line, then rerun ({FIX})")])
            indent = re.match(r"^(\s*)", lines[at - 1]).group(1)
            edits.setdefault(n.rel, []).append((at, 1, f"{indent}#[cfg(tp{want})]"))
    lib = a.crate.texts.get("src/lib.rs")
    if lib is not None and CRATE_ALLOW not in [line.strip() for line in lib.splitlines()]:
        lines = lib.split("\n")
        # Directly above the crate's first code line (past its comments and blank lines), so it joins the run of
        # inner attributes with no blank line inside it, as rustfmt wants.
        at = next((i for i, line in enumerate(lines, 1) if line.strip() and not line.lstrip().startswith("//")), len(lines))
        edits.setdefault("src/lib.rs", []).append((at, 1, CRATE_ALLOW))
    for rel, ops in edits.items():
        lines = a.crate.texts[rel].split("\n")
        for line, order, text in sorted(ops, key=lambda op: (-op[0], op[1])):
            if order == 1:
                lines.insert(line - 1, text)
            elif text is None:
                del lines[line - 1]
            else:
                lines[line - 1] = text
        (root / rel).write_text("\n".join(lines), encoding="utf-8")
    return sorted(edits)


def main(argv: list[str], root: Path | None = None) -> int:
    root = root or Path(__file__).resolve().parents[2]
    if argv[1:] == ["apply"]:
        try:
            changed = apply(root)
        except Refusal as err:
            print(f"test_parts: refused, nothing written: {err}", file=sys.stderr)
            return 1
        print(f"test_parts: {len(changed)} files changed")
        # What apply cannot fix (a stale table row, a bad shared entry, a test macro in a container) still fails.
        left = check(root)
        for f in left:
            print(f"{f.path}:{f.line}: {f.code}: {f.message}", file=sys.stderr)
        return 1 if left else 0
    if argv[1:] == ["check"]:
        findings = check(root)
        for f in findings:
            print(f"{f.path}:{f.line}: {f.code}: {f.message}", file=sys.stderr)
        print(f"test_parts: {len(findings)} findings")
        return 1 if findings else 0
    print("usage: test_parts.py check|apply", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))



