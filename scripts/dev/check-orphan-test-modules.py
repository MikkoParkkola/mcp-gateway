#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when a ``.rs`` file under ``src/`` is in no compilation unit.

A test file that no module declares is never compiled and never run, yet it
reads exactly like coverage: it sits next to its siblings, its assertions are
specific, and it can be cited as proof of a behaviour nobody has ever observed.
``cargo test`` cannot report it, because from the compiler's side the file does
not exist. MIK-7538 found one such file being cited as evidence in a release
ledger, in two merged design documents and in three implementation briefs.

Two earlier versions of this check were wrong, and both failure modes are
pinned by ``test_check_orphan_test_modules.py``:

* A **directory-scoped** sweep reported 72 false orphans out of 113 files,
  because a module may be declared from a sibling by ``#[path = "..."]``
  rather than by a ``mod`` line in the directory's own ``mod.rs``.
* A **name-matching** sweep hid real orphans, because it asked only whether
  the *stem* appeared anywhere. Five stems are duplicated in this tree --
  ``admission_tests``, ``provider_tests``, ``runtime_tests``,
  ``service_tests``, ``store_tests`` -- so declaring one silently answered for
  its twin in another directory.

A third version still let orphans through: it counted a declaration from
*any* file, including a file that was itself undeclared. MIK-7518's
``invoke/suggestion.rs`` lost its ``mod suggestion;`` in an unrelated docs
commit, and its ``#[path]`` declaration of ``suggestion_authz_tests.rs`` kept
answering for a test file the compiler no longer saw. So the check now walks
declarations from the crate roots (``src/lib.rs``, ``src/main.rs``,
``src/bin/*.rs`` and the ``tests``/``benches``/``examples`` targets) and
reports every source under ``src/`` the walk does not reach -- not only
``*_tests.rs``, because an orphaned production module strands its tests too.
Declarations behind a ``#[cfg]`` still count as reached: the file is in a
compilation unit for some configuration.

So declarations are resolved to the file path they actually name, following
Rust's own rules, and compared against the file on disk. Three further traps
the resolution has to avoid: a ``mod foo { .. }`` block declares an *inline*
module and backs no file; a ``mod`` line inside a comment or a string declares
nothing; and ``#[path]`` is relative to the directory of the declaring file.

Usage:
    check-orphan-test-modules.py    # check, exit 1 when a file is unreachable
"""

from __future__ import annotations

import collections
import enum
import functools
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules"}

# One token stream over code with comments and literal contents blanked:
# a `#[path = "` (or raw `r#"`) opener (its value is read back from the literal table), a
# `mod name;` (backs a file) or `mod name {` (inline, backs none), and the
# braces that tell which inline modules enclose a declaration.
TOKEN = re.compile(
    r"""(?P<path>\#\s*\[\s*path\s*=\s*)(?:r\#*)?(?P<quote>")"""
    r"""|(?P<cfg>\#(?P<inner>!)?\s*\[\s*cfg\s*\()"""
    r"""|(?P<attr>\#!?\s*\[)"""
    r"""|\bmod\s+(?:r\#)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<end>[;{])"""
    r"""|(?P<open>\{)|(?P<close>\})|(?P<semi>;)"""
)


def cfg_is_test(expr: str) -> bool:
    """Whether a `#[cfg(<expr>)]` compiles only under test: the predicate
    is false whenever `test` is. `test` requires test; `all(..)` does when
    any operand does; `any(..)` only when every operand does; `not(..)`, a
    `key = ".."` pair and any other atom never do (they build outside tests),
    and `test_mode` is not `test`. An unbalanced predicate reads as false
    here; a caller that must fail closed checks the balance itself
    (MIK-8405.SPLIT.5; the one cfg judgement, shared with
    scripts/release/check_inventory_rows.py, scripts/ci/check-request-panics.py
    and the timing-asserts gate). Literal contents are blanked first, so a
    comma inside a quoted value separates no operand (MIK-9387.TCFG.1)."""
    expr = blank(expr)[0].strip()
    if expr == "test":
        return True
    opener = re.match(r"(all|any)\s*\(", expr)
    if not (opener and expr.endswith(")")):
        return False
    operands, depth, start = [], 0, opener.end()
    for i in range(opener.end(), len(expr) - 1):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
        elif ch == "," and depth == 0:
            operands.append(expr[start:i])
            start = i + 1
    if depth:
        return False
    operands.append(expr[start : len(expr) - 1])
    operands = [o for o in operands if o.strip()]
    if not operands:
        return False
    judged = [cfg_is_test(o) for o in operands]
    return any(judged) if opener.group(1) == "all" else all(judged)


def cfg_expression(code: str, start: int) -> str:
    """The expression of a `#[cfg(` whose `(` ends just before `start`, up to
    its balancing `)`. Literal contents are already blanked."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"(": 1, ")": -1}.get(code[i], 0)
        i += 1
    return code[start : i - 1]
RAW_STRING = re.compile(r'[bc]?r(#*)"')


def blank(text: str) -> tuple[str, dict[int, str]]:
    """Blank comments and literal contents; keep quotes, newlines and offsets.

    A `mod foo;` inside a comment or a string declares nothing. Left in, it
    would let a commented-out declaration keep answering for a file the
    compiler no longer sees -- the exact shape this guard exists to catch.
    Block comments nest in Rust, so they are matched by depth. Returns the
    blanked text and each string literal's value keyed by its opening quote.
    """
    out = list(text)
    literals: dict[int, str] = {}
    n = len(text)

    def wipe(start: int, stop: int) -> None:
        for k in range(start, stop):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        ident_before = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
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
            wipe(i, j)
            i = j
        elif not ident_before and (m := RAW_STRING.match(text, i)):
            quote = m.end() - 1
            j = text.find('"' + m.group(1), m.end())
            j = n if j < 0 else j
            literals[quote] = text[m.end() : j]
            wipe(m.end(), j)
            i = j + 1 + len(m.group(1))
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            literals[i] = text[i + 1 : j]
            wipe(i + 1, j)
            i = j + 1
        elif text[i] == "'":
            # A char literal ('x', '\n', '"') or a lifetime ('a): only the
            # literal forms are skipped, so a lifetime never swallows code.
            # Their contents are blanked: a '{' or '[' is not a brace.
            if text.startswith("\\", i + 1):
                j = text.find("'", i + 3)
                j = n if j < 0 else j
                wipe(i + 1, j)
                i = j + 1
            elif i + 2 < n and text[i + 2] == "'":
                wipe(i + 1, i + 2)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return "".join(out), literals


def src_sources() -> list[Path]:
    """Every Rust source under ``src/``, minus build output."""
    return sorted(
        path
        for path in ROOT.joinpath("src").rglob("*.rs")
        if not SKIP_DIRS.intersection(path.relative_to(ROOT).parts)
    )


def crate_roots() -> list[Path]:
    """Every file cargo compiles as the root of a crate in this package."""
    src = ROOT / "src"
    roots = [src / "lib.rs", src / "main.rs", *src.joinpath("bin").glob("*.rs")]
    roots += src.joinpath("bin").glob("*/main.rs")
    for target in ("tests", "benches", "examples"):
        roots += ROOT.joinpath(target).glob("*.rs")
        roots += ROOT.joinpath(target).glob("*/main.rs")
    return [root for root in roots if root.is_file()]


def module_dir(source: Path, owns_dir: bool) -> Path:
    """The directory a plain `mod foo;` in `source` resolves against.

    A crate root, a file loaded through `#[path]` (rustc treats it as a
    mod-rs file), `mod.rs`, `lib.rs` and `main.rs` own their directory; any
    other file owns a subdirectory named after itself.
    """
    if owns_dir or source.name in {"mod.rs", "lib.rs", "main.rs"}:
        return source.parent
    return source.parent / source.stem


def declarations(source: Path, owns_dir: bool) -> set[tuple[Path, bool]]:
    """[`declarations_with_cfg`] without the test flag."""
    return {(path, via_path) for path, via_path, _ in declarations_with_cfg(source, owns_dir)}


def declarations_with_cfg(source: Path, owns_dir: bool) -> set[tuple[Path, bool, bool]]:
    """Resolve every file-backed declaration in `source` to the path it names.

    Per the Rust reference: a plain `mod name;` resolves under the module
    directory plus each enclosing inline module; a `#[path]` resolves against
    the declaring file's directory at top level, and against the module
    directory plus enclosing inline modules inside one. A `#[path]`
    declaration names only its path, never also the default file. Each result
    carries whether it was reached through `#[path]`, which decides where ITS
    child modules resolve, and whether the declaration compiles only under
    test: a test `#[cfg]` on it or on an enclosing inline module
    (MIK-8405.SPLIT.5). A `#[cfg]` is dropped at the end of the item it
    belongs to (`;`, `{` or `}`), so one on a `use` or `fn` never reaches a
    later `mod`. An inner `#![cfg(test)]` makes the file (or the inline
    module it opens) test-only, so everything it declares is too. The body
    of any other attribute is skipped whole, so a brace inside one (say
    `#[doc = concat!{..}]`) never drops a pending `#[cfg]`.
    """
    return _scan(source, owns_dir)[0]


def file_is_test(source: Path) -> bool:
    """Whether `source` opens with an inner `#![cfg(test)]`: the whole file
    then compiles only under test."""
    return _scan(source, True)[1]


# `name!(`, `name !{`, `macro_rules! r#name {`; identifiers may be Unicode.
# Any non-ASCII character counts as an identifier character (a combining mark
# too): the safe side, since a false match only stops an inner cfg marking.
_ID = r"(?:r#)?(?:[A-Za-z_]|[^\x00-\x7f])(?:\w|[^\x00-\x7f])*"
MACRO_CALL = re.compile(_ID + r"\s*!\s*(?:" + _ID + r"\s*)?[(\[{]")


def macro_spans(code: str) -> list[tuple[int, int]]:
    """Each macro's tokens in blanked `code`: a `name!(..)`, `name![..]` or
    `name!{..}` call, or a `macro_rules! name {..}` body. A `mod` written there
    is input the macro may drop or rewrite, so its inner attributes mark
    nothing (MIK-9387.TCFG.1). An unclosed one runs to the end."""
    spans, pos = [], 0
    while m := MACRO_CALL.search(code, pos):
        open_at, depth, end = m.end() - 1, 0, len(code)
        for i in range(open_at, len(code)):
            depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(code[i], 0)
            if depth == 0:
                end = i + 1
                break
        spans.append((open_at, end))
        pos = end
    return spans


def _scan(source: Path, owns_dir: bool) -> tuple[set[tuple[Path, bool, bool]], bool]:
    code, literals = blank(source.read_text(encoding="utf-8", errors="replace"))
    macros = macro_spans(code)
    base = module_dir(source, owns_dir)
    declared: set[tuple[Path, bool, bool]] = set()
    # Each open brace: the inline module name it opens (None for any other
    # block) and whether that block compiles only under test.
    inline: list[tuple[str | None, bool]] = []
    pending_path: str | None = None
    pending_test = False
    file_test = False
    # Whether each scope (the file, then each open brace) is still in its
    # leading run of inner attributes: an inner cfg counts only there. Inside
    # a macro's tokens or after an item it marks nothing, the safe side
    # (MIK-9387.TCFG.1).
    leading = [True]
    pos = 0
    while m := TOKEN.search(code, pos):
        if code[pos : m.start()].strip():
            leading[-1] = False
        pos = m.end()
        enclosing_test = file_test or any(test for _, test in inline)
        inner_attr = m.group("cfg") and m.group("inner") or (m.group("attr") and "!" in m.group("attr"))
        if not inner_attr:
            leading[-1] = False
        if m.group("quote"):
            pending_path = literals.get(m.start("quote"))
        elif m.group("cfg"):
            test = cfg_is_test(cfg_expression(code, m.end()))
            pos = attribute_end(code, code.index("[", m.start()) + 1)
            if not m.group("inner"):
                pending_test = pending_test or test
            elif not leading[-1] or any(s < m.start() < e for s, e in macros):
                pass
            elif inline:
                inline[-1] = (inline[-1][0], inline[-1][1] or test)
            else:
                file_test = file_test or test
        elif m.group("attr"):
            pos = attribute_end(code, m.end())
        elif m.group("name"):
            nested = [name for name, _ in inline if name]
            test = pending_test or enclosing_test
            if m.group("end") == "{":
                inline.append((m.group("name"), test))
                leading.append(True)
            elif pending_path is not None:
                start = base.joinpath(*nested) if nested else source.parent
                declared.add(((start / pending_path).resolve(), True, test))
            else:
                directory = base.joinpath(*nested)
                declared.add(((directory / f"{m.group('name')}.rs").resolve(), False, test))
                declared.add(((directory / m.group("name") / "mod.rs").resolve(), False, test))
            pending_path, pending_test = None, False
        elif m.group("open"):
            inline.append((None, pending_test or enclosing_test))
            leading.append(True)
            pending_path, pending_test = None, False
        elif m.group("close"):
            if inline:
                inline.pop()
                leading.pop()
            pending_path, pending_test = None, False
        elif m.group("semi"):
            pending_path, pending_test = None, False
    return declared, file_test


def attribute_end(code: str, start: int) -> int:
    """The offset just past the `]` closing an attribute whose `[` ends just
    before `start`. Literal contents are already blanked."""
    depth, i = 1, start
    while i < len(code) and depth:
        depth += {"[": 1, "]": -1}.get(code[i], 0)
        i += 1
    return i


# ---------------------------------------------------------------------------
# cfg item extents, by a parser. Shared with the timing-asserts,
# request-panics and inventory gates. tree-sitter comes from the gates' own
# environment (scripts/gate-env) and is imported only here, so the orphan gate
# itself still runs on the system Python.


class SafeSide(enum.Enum):
    """Where a caller wants an unsure extent to land."""

    # Looking for test code (the timing gate): an unsure item runs long.
    LEAN_LONG = "lean_long"
    # Looking for product code (request-panics, inventory): an unsure item is
    # left as product code.
    LEAN_SHORT = "lean_short"


class CfgItem(NamedTuple):
    """One item under a target cfg: character offsets [start, end) of the
    attribute through its construct, and its 1-based first and last lines."""

    start: int
    end: int
    first_line: int
    last_line: int


class CfgItems(NamedTuple):
    items: tuple[CfgItem, ...]
    # The tree has errors; `known_gap` when they are exactly a listed gap.
    parse_errors: bool
    known_gap: bool
    # Why each unsure case was resolved by the caller's side, for its report.
    unsure: tuple[str, ...]


# Today's grammar gaps of the pinned tree-sitter-rust: each file's errors as a
# count of (kind, normalized text of the error node). A file whose errors
# differ in any way (a new error, a repeat, a changed node) is unsure as a
# whole, and a pin in test_cfg_items.py keeps each entry matching its file.
KNOWN_GAPS: dict[str, collections.Counter] = {
    "src/gateway/authz.rs": collections.Counter({("ERROR", "raw @"): 1}),
    "src/gateway/meta_mcp/invoke/send.rs": collections.Counter(
        {
            ("ERROR", "#[cfg("): 1,
            ("MISSING }", ""): 1,
            ("ERROR", '"cost-governance")] cost_warnings, prompt_cache_key, outbound_retry,'): 1,
            ("ERROR", ", }"): 1,
        }
    ),
    "src/gateway/meta_mcp/invoke/post_dispatch.rs": collections.Counter(
        {
            ("ERROR", "#[cfg("): 1,
            ("MISSING }", ""): 1,
            ("ERROR", '"cost-governance")]'): 1,
            ("ERROR", ","): 1,
            ("ERROR", "}"): 1,
        }
    ),
}

# The attribute is its construct's first child.
PARENT_OWNED = frozenset({"field_initializer", "shorthand_field_initializer", "match_arm"})
# The attribute precedes its construct in a list.
LIST_OWNED = frozenset(
    {
        "source_file",
        "declaration_list",
        "block",
        "field_declaration_list",
        "ordered_field_declaration_list",
        "enum_variant_list",
        "parameters",
        "array_expression",
    }
)
NOT_A_CONSTRUCT = frozenset({"attribute_item", "inner_attribute_item", "line_comment", "block_comment"})
CFG_IN_TEXT = re.compile(r"#!?\[cfg\(")
CFG_ATTR = re.compile(r"#\s*!?\s*\[\s*cfg\s*\(")


@functools.lru_cache(maxsize=1)
def _rust_parser():
    try:
        import tree_sitter_rust
        from tree_sitter import Language, Parser
    except ImportError as err:
        raise SystemExit(
            f"the cfg item finder needs the gates' environment ({err}); "
            "run: UV_MALWARE_CHECK=1 uv sync --locked --project scripts/gate-env, "
            "then run this gate with scripts/gate-env/.venv/bin/python"
        ) from None
    return Parser(Language(tree_sitter_rust.language()))


def _owner(attr):
    """The node an attribute marks, or None when the owner table does not
    know its place (an unsure case, resolved by the caller's side)."""
    parent = attr.parent
    if parent is None:
        return None
    if attr.type == "inner_attribute_item":
        if parent.type == "source_file":
            return parent
        holder = parent.parent
        if parent.type == "declaration_list" and holder is not None and holder.type in ("mod_item", "impl_item", "trait_item"):
            return holder
        if parent.type == "block" and holder is not None and holder.type == "function_item":
            return holder
        return None
    if parent.type in PARENT_OWNED:
        return parent
    if parent.type not in LIST_OWNED:
        return None
    node = attr.next_named_sibling
    while node is not None and node.type in NOT_A_CONSTRUCT:
        node = node.next_named_sibling
    if node is not None and parent.type == "ordered_field_declaration_list" and node.type == "visibility_modifier":
        node = node.next_named_sibling  # a `pub` tuple field spans through its type
        while node is not None and node.type in NOT_A_CONSTRUCT:
            node = node.next_named_sibling
    return node


def _cfg_predicates(attr_text: str) -> list[str]:
    """The predicate of each `#[cfg(..)]` in `attr_text` (literals blanked)."""
    code = blank(attr_text)[0]
    return [cfg_expression(code, m.end()) for m in CFG_ATTR.finditer(code)]


def _errors(root, src: bytes) -> list:
    """Each ERROR and missing node, outermost only (an ERROR's insides are
    not walked): (kind, normalized text, start byte, end byte)."""
    found = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            kind = f"MISSING {node.type}" if node.is_missing else "ERROR"
            text = " ".join(src[node.start_byte : node.end_byte].decode("utf-8", "replace").split())[:80]
            found.append((kind, text, node.start_byte, node.end_byte))
            if node.type == "ERROR":
                continue
        stack.extend(reversed(node.children))
    return found


def _error_signature(errors: list) -> collections.Counter:
    """The file's errors as a count of (kind, normalized node text): a repeat
    of a listed error, or any new one, no longer matches its entry."""
    return collections.Counter((kind, text) for kind, text, _, _ in errors)


def _enclosing_function(node):
    """The (start, end) bytes of the outermost function holding `node`, or
    None: error recovery in any function reaches every function it holds."""
    found = None
    up = node.parent
    while up is not None:
        if up.type == "function_item":
            found = (up.start_byte, up.end_byte)
        up = up.parent
    return found


def _walk_cfg(root, src: bytes, is_target):
    """(start byte, end byte or None, fallback end, reason, enclosing
    function) for each outermost target cfg attribute and each macro body
    holding one. `end` is None for an unsure case."""
    found = []

    def target(text: str) -> bool:
        return any(is_target(p) for p in _cfg_predicates(text))

    def attribute_targets(attr) -> bool:
        """The attribute is itself `cfg(P)` with a target P: by its own name,
        never by a `cfg` mentioned inside another attribute's arguments."""
        inner = next((c for c in attr.named_children if c.type == "attribute"), None)
        # A comment is a token like any other: `#[cfg /* why */ (test)]` is cfg(test).
        named = inner.named_children if inner is not None else []
        parts = [c for c in named if c.type not in ("line_comment", "block_comment")]
        if len(parts) != 2 or parts[0].type != "identifier" or parts[1].type != "token_tree":
            return False
        if src[parts[0].start_byte : parts[0].end_byte] != b"cfg":
            return False
        args = blank(src[parts[1].start_byte : parts[1].end_byte].decode("utf-8", "replace"))[0].strip()
        return args.startswith("(") and args.endswith(")") and is_target(args[1:-1])

    # An explicit stack of (node, inside_end): the children of `node` that
    # start before `inside_end` lie in an item already taken.
    stack = [(root, -1)]
    while stack:
        node, inside_end = stack.pop()
        pending = []
        for child in node.children:
            if child.start_byte < inside_end:
                continue
            if child.type in ("attribute_item", "inner_attribute_item"):
                # An attribute is metadata, never a code body: a `cfg` named
                # inside another attribute's arguments marks nothing.
                if not attribute_targets(child):
                    continue
                owner = _owner(child)
                scope = _enclosing_function(child)
                if owner is None:
                    found.append((child.start_byte, None, node.end_byte, "owner not known", scope))
                else:
                    start = min(child.start_byte, owner.start_byte)
                    found.append((start, max(owner.end_byte, child.end_byte), None, "", scope))
                    inside_end = max(inside_end, owner.end_byte)
                continue
            if child.type in ("macro_invocation", "macro_definition"):
                body = "".join(blank(src[child.start_byte : child.end_byte].decode("utf-8", "replace"))[0].split())
                if any(target(m.group(0) + body[m.end() :]) for m in CFG_IN_TEXT.finditer(body)):
                    found.append((child.start_byte, None, child.end_byte, "cfg inside a macro body", _enclosing_function(child)))
                    inside_end = max(inside_end, child.end_byte)
                    continue
            pending.append((child, inside_end))
        stack.extend(reversed(pending))
    # A level's attributes are found before its children's: restore source order.
    return sorted(found, key=lambda f: f[0])


def _char_offsets(text: str, src: bytes):
    """A byte offset of `src` (the UTF-8 encoding of `text`) as a character
    offset of `text`; the identity for an ASCII file."""
    if len(src) == len(text):
        return lambda b: b
    starts = [0] * (len(src) + 1)
    k = 0
    for i, ch in enumerate(text):
        for _ in range(len(ch.encode("utf-8"))):
            starts[k] = i
            k += 1
    starts[len(src)] = len(text)
    return lambda b: starts[b]


def _item(text: str, start: int, end: int) -> CfgItem:
    return CfgItem(start, end, text.count("\n", 0, start) + 1, text.count("\n", 0, max(start, end - 1)) + 1)


def cfg_items(text: str, side: SafeSide, is_target=None, path: str = "", report: dict | None = None) -> CfgItems:
    """Each outermost item in `text` under a cfg that `is_target` accepts
    (default `cfg_is_test`), by its own extent, with every unsure case
    resolved by `side`: a file whose parse errors are not exactly a listed
    gap (the whole file), an attribute whose place the owner table does not
    know, an item touching a listed error, and a macro body holding a target
    cfg. LEAN_LONG makes an unsure case test code to its fallback end;
    LEAN_SHORT leaves it product code."""
    is_target = is_target or cfg_is_test
    src = text.encode("utf-8")
    tree = _rust_parser().parse(src)
    root = tree.root_node
    to_char = _char_offsets(text, src)
    errors = root.has_error
    error_nodes = _errors(root, src) if errors else []
    known = errors and _error_signature(error_nodes) == KNOWN_GAPS.get(path)
    if report is not None:
        report[path] = (bool(errors), bool(known))
    if errors and not known:
        whole = (_item(text, 0, len(text)),) if side is SafeSide.LEAN_LONG else ()
        return CfgItems(whole, True, False, ("parse errors outside the known-gap list",))
    error_ranges = [(a, b) for _, _, a, b in error_nodes]
    items: list[CfgItem] = []
    unsure: list[str] = []
    for start, end, fallback, reason, scope in _walk_cfg(root, src, is_target):
        # Recovery can move extents anywhere inside a broken function, so an
        # item touching a listed error, or in a function holding one, is unsure.
        near = [(start, end)] + ([scope] if scope else [])
        if end is not None and any(a < e and s < b for a, b in error_ranges for s, e in near):
            end, fallback, reason = None, end, "item near a known parse error"
        if end is None:
            unsure.append(f"{reason} at line {text.count(chr(10), 0, to_char(start)) + 1}")
            if side is SafeSide.LEAN_LONG:
                items.append(_item(text, to_char(start), to_char(fallback)))
            continue
        items.append(_item(text, to_char(start), to_char(end)))
    return CfgItems(tuple(items), bool(errors), bool(known), tuple(unsure))


def parse_error_summary(report: dict) -> str:
    """The line each gate prints: how many files it parsed with errors and
    how many of those match the known-gap list, so a grammar regression or a
    new gap shows as a changed count. `report` is what `cfg_items` filled."""
    errors = sorted(path for path, (bad, _) in report.items() if bad)
    known = [path for path in errors if report[path][1]]
    line = f"cfg items: {len(report)} files parsed, {len(errors)} with parse errors ({len(known)} on the known-gap list)"
    unlisted = [path for path in errors if not report[path][1]]
    return line + (": unsure as a whole: " + ", ".join(unlisted) if unlisted else "")


def item_extents_ignoring_errors(text: str, is_target=None) -> list[tuple[int, int]]:
    """(first line, last line) of each target cfg item as the tree reads it,
    errors or not: the locality check behind the known-gap list."""
    src = text.encode("utf-8")
    to_char = _char_offsets(text, src)
    root = _rust_parser().parse(src).root_node
    out = []
    for start, end, _, _, _ in _walk_cfg(root, src, is_target or cfg_is_test):
        if end is not None:
            item = _item(text, to_char(start), to_char(end))
            out.append((item.first_line, item.last_line))
    return out


def reachable() -> set[Path]:
    """Files reached by following declarations from the crate roots only.

    A declaration inside an unreached file declares nothing: that file is
    not compiled, so neither is anything it names.
    """
    roots = {root.resolve() for root in crate_roots()}
    seen: set[tuple[Path, bool]] = set()
    stack = [(root, True) for root in roots]
    while stack:
        path, owns_dir = stack.pop()
        if (path, owns_dir) in seen or not path.is_file():
            continue
        seen.add((path, owns_dir))
        stack.extend(declarations(path, owns_dir))
    return {path for path, _ in seen}


def library_roots() -> list[Path]:
    """The crate roots that build outside tests: the library and the
    binaries. `tests/`, `benches/` and `examples/` targets build only for
    their own commands, so what they alone reach is test-only."""
    src = ROOT / "src"
    roots = [src / "lib.rs", src / "main.rs", *src.joinpath("bin").glob("*.rs")]
    roots += src.joinpath("bin").glob("*/main.rs")
    return [root for root in roots if root.is_file()]


def compiled_outside_tests() -> set[Path]:
    """Files reached from a library or binary root through declarations none
    of which is test-only."""
    seen: set[tuple[Path, bool]] = set()
    stack = [(root.resolve(), True) for root in library_roots()]
    while stack:
        path, owns_dir = stack.pop()
        if (path, owns_dir) in seen or not path.is_file():
            continue
        declared, file_test = _scan(path, owns_dir)
        if file_test:
            continue
        seen.add((path, owns_dir))
        stack.extend((child, via_path) for child, via_path, test in declared if not test)
    return {path for path, _ in seen}


def test_only_files(live: set[Path] | None = None) -> set[Path]:
    """Files compiled only under test: reachable from a crate root, but not
    through any chain of non-test declarations from the library or a binary
    (MIK-8405.SPLIT.5). check_inventory_rows.py keeps their functions out of
    the critical-function inventory. `live` is `reachable()`, when the
    caller has it already."""
    return (reachable() if live is None else live) - compiled_outside_tests()


def orphans() -> list[Path]:
    live = reachable()
    return [path for path in src_sources() if path.resolve() not in live]


def main() -> int:
    found = orphans()
    total = len(src_sources())

    if found:
        print(f"Unreachable source files ({len(found)}):", file=sys.stderr)
        for path in found:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        print(
            "\nEach is compiled into nothing and run by nothing. Declare it from a\n"
            "module the crate root reaches (for a test file,\n"
            '`#[cfg(test)] #[path = "<file>.rs"] mod <stem>;`), or delete it.\n'
            "A file in no compilation unit is neither code nor a test.",
            file=sys.stderr,
        )
        return 1

    print(f"{total} source files under src/, all reachable from a crate root.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
