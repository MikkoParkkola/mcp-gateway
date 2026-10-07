#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Zero-unclassified check for docs/design/surface-4.0.md (MIK-8044).

Extracts every item on the five user-facing surfaces from the source and
fails when one is missing from the inventory, carries no valid class, or
when the inventory lists an item the code no longer has.

Surfaces: config (gateway.yaml keys), cli (subcommands and flags),
env (MCP_GATEWAY_* variables), routes (HTTP listener paths),
lib (crate-root public items in src/lib.rs).

Usage:
  check_surface_inventory.py            check the doc, exit 1 on any gap
  check_surface_inventory.py --list S   print extracted items of surface S
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DOC = ROOT / "docs/design/surface-4.0.md"
CLASSES = {"KEEP", "AUTO", "INTERNAL", "REMOVE"}
SURFACES = ("config", "cli", "env", "routes", "lib")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_test_path(path: Path) -> bool:
    """Test-only sources never define user surface."""
    s = rel(path)
    name = path.name
    return (
        "/tests/" in s
        or re.search(r"_tests?/", s) is not None
        or name.endswith("_tests.rs")
        or name in {"tests.rs", "test_support.rs"}
        or "fixture" in name
        or name.startswith("test_")
    )


def src_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.rs") if not is_test_path(p))


def scan(text: str) -> tuple[str, str]:
    """Return (code, mask), both the length of `text`.

    `code` blanks comments; `mask` also blanks string and char literal
    contents, so brace matching and splitting never see a `{` or `,` inside
    a literal. Newlines survive in both, keeping line numbers.
    """
    code, mask = list(text), list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int, both: bool) -> None:
        for k in range(a, b):
            if text[k] != "\n":
                mask[k] = " "
                if both:
                    code[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j, True)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j, True)
            i = j
        elif (rm := re.match(r'(b?r)(#*)"', text[i : i + 12])) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + rm.group(2)
            j = text.find(close, i + rm.end())
            j = n if j < 0 else j + len(close)
            blank(i + rm.end(), j - len(close), False)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j, False)
            i = j + 1
        elif c == "'" and (cm := re.match(r"'(\\.[^']*|[^'\\])'", text[i : i + 12])):
            blank(i + 1, i + cm.end() - 1, False)
            i += cm.end()
        else:
            i += 1
    return "".join(code), "".join(mask)


def matching_brace(mask: str, open_idx: int) -> int:
    """Index of the bracket closing the one at `open_idx`."""
    depth = 0
    for i in range(open_idx, len(mask)):
        c = mask[i]
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced brackets")


def prod_scan(path: Path) -> tuple[str, str]:
    """`scan` of a file with every `#[cfg(test)]`-gated inline module blanked."""
    code, mask = scan(path.read_text(encoding="utf-8"))
    for m in reversed(list(re.finditer(r"#\[cfg\((?:all\()?test\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", mask))):
        end = matching_brace(mask, m.end() - 1)
        blank = re.sub(r"[^\n]", " ", code[m.start() : end + 1])
        code = code[: m.start()] + blank + code[end + 1 :]
        mask = mask[: m.start()] + blank + mask[end + 1 :]
    return code, mask


def split_top(code: str, mask: str, sep: str = ",") -> list[tuple[int, str]]:
    """Split `code` on `sep` outside brackets; returns (offset, piece) pairs."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(mask):
        if c in "<([{":
            depth += 1
        elif c in ">)]}" and not (c == ">" and i and mask[i - 1] == "-"):
            depth -= 1
        if c == sep and depth == 0:
            parts.append((start, code[start:i]))
            start = i + 1
    if code[start:].strip():
        parts.append((start, code[start:]))
    return parts


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


# ── Rust item model ──────────────────────────────────────────────────────────

@dataclass
class Member:
    """A struct field or an enum variant."""

    name: str
    attrs: str  # every `#[...]` text joined
    ty: str  # field type, or variant payload ("" unit, "{...}" struct, "(...)" tuple)
    line: int


@dataclass
class Item:
    kind: str  # "struct" or "enum"
    name: str
    file: Path
    line: int
    attrs: str
    members: list[Member] = field(default_factory=list)
    tuple_body: str | None = None  # `struct X(T);`


def leading_attrs(code: str, mask: str) -> tuple[str, int]:
    """Attributes at the head of a member chunk, and where the rest starts."""
    attrs, i = [], len(code) - len(code.lstrip())
    while code.startswith("#[", i):
        end = matching_brace(mask, i + 1)
        attrs.append(code[i + 2 : end])
        i = end + 1
        i += len(code[i:]) - len(code[i:].lstrip())
    return " ".join(attrs), i


ITEM_RE = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+([A-Z]\w*)(?:<[^>{(]*>)?\s*(?:where[^{]*)?([{(;])")
OUTER_ATTRS_RE = re.compile(r"((?:#\[[^\n]*\]\s*)*)$")


def parse_items(path: Path) -> list[Item]:
    code, mask = prod_scan(path)
    items = []
    for m in ITEM_RE.finditer(mask):
        kind, name, opener = m.group(1), m.group(2), m.group(3)
        before = code[max(0, m.start() - 600) : m.start()]
        outer = OUTER_ATTRS_RE.search(before).group(1)
        item = Item(kind, name, path, line_of(code, m.start(1)), outer)
        start = m.end() - 1
        if opener == ";":
            items.append(item)
            continue
        end = matching_brace(mask, start)
        if opener == "(":
            item.tuple_body = code[start + 1 : end]
            items.append(item)
            continue
        body_c, body_m = code[start + 1 : end], mask[start + 1 : end]
        for off, chunk in split_top(body_c, body_m):
            attrs, k = leading_attrs(chunk, body_m[off : off + len(chunk)])
            rest = re.sub(r"^pub(\([^)]*\))?\s+", "", chunk[k:].strip())
            if not rest:
                continue
            ln = line_of(code, start + 1 + off + k)
            if kind == "struct":
                fm = re.match(r"(?:r#)?(\w+)\s*:\s*(.+)$", rest, re.S)
                if fm:
                    item.members.append(Member(fm.group(1), attrs, " ".join(fm.group(2).split()), ln))
            else:
                vm = re.match(r"(\w+)\s*(.*)$", rest, re.S)
                if vm:
                    payload = vm.group(2).strip()
                    if not payload.startswith(("{", "(")):
                        payload = ""  # unit variant, maybe with a discriminant
                    item.members.append(Member(vm.group(1), attrs, payload, ln))
        items.append(item)
    return items


def attr_bodies(attrs: str, name: str) -> list[str]:
    """Bodies of every `name(...)` attribute in `attrs`."""
    _, mask = scan(attrs)
    out = []
    for m in re.finditer(rf"(?<![\w:]){name}\(", mask):
        end = matching_brace(mask, m.end() - 1)
        out.append(attrs[m.end() : end])
    return out


def attr_value(attrs: str, name: str, key: str) -> str | None:
    """`key = "v"` inside `name(...)`: "v"; bare `key`: ""; absent: None."""
    for body in attr_bodies(attrs, name):
        for _, part in split_top(*scan(body)):
            part = part.strip()
            kv = re.match(rf"{key}\s*=\s*(.+)$", part, re.S)
            if kv:
                return kv.group(1).strip().strip('"')
            if part == key:
                return ""
    return None


def serde_attr(attrs: str, key: str) -> str | None:
    return attr_value(attrs, "serde", key)


def member_fields(payload: str, path: Path) -> list[Member]:
    """Fields of a `{ ... }` enum-variant payload."""
    code, mask = scan(payload)
    end = matching_brace(mask, 0)
    out = []
    for off, chunk in split_top(code[1:end], mask[1:end]):
        attrs, k = leading_attrs(chunk, mask[1 + off : 1 + off + len(chunk)])
        fm = re.match(r"(?:pub\s+)?(?:r#)?(\w+)\s*:\s*(.+)$", chunk[k:].strip(), re.S)
        if fm:
            out.append(Member(fm.group(1), attrs, " ".join(fm.group(2).split()), 0))
    return out


# ── Surface: config ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Entry:
    """One extracted surface item."""

    id: str
    file: str
    line: int
    note: str = ""


class Index:
    """Every struct and enum in the non-test sources, by name."""

    def __init__(self) -> None:
        self.by_name: dict[str, list[Item]] = {}
        self.manual: set[str] = set()
        for path in src_files():
            for item in parse_items(path):
                self.by_name.setdefault(item.name, []).append(item)
            text = path.read_text(encoding="utf-8")
            for m in re.finditer(r"impl<'de>\s+(?:serde::)?Deserialize<'de>\s+for\s+(\w+)", text):
                self.manual.add(m.group(1))

    def resolve(self, qualified: str, near: Path, derive: str = "Deserialize") -> Item | None:
        name = qualified.split("::")[-1]
        cands = [i for i in self.by_name.get(name, []) if re.search(rf"derive\([^)]*\b({derive})\b", i.attrs)]
        if len(cands) <= 1:
            return cands[0] if cands else None
        mods = [p for p in qualified.split("::")[:-1] if p not in {"crate", "self", "super"}]
        if mods:
            hits = [i for i in cands if all(m in rel(i.file) for m in mods)]
            if len(hits) == 1:
                return hits[0]
        top = lambda f: f.relative_to(SRC).parts[0]  # noqa: E731
        for test in (
            lambda i: i.file == near,
            lambda i: i.file.parent == near.parent,
            lambda i: top(i.file) == top(near),
        ):
            same = [i for i in cands if test(i)]
            if len(same) == 1:
                return same[0]
        raise SystemExit(f"ambiguous type {qualified} near {rel(near)}: {[rel(i.file) for i in cands]}")


SEQ = {"Vec", "BTreeSet", "HashSet", "VecDeque", "IndexSet", "SmallVec"}
MAP = {"HashMap", "BTreeMap", "IndexMap"}
WRAP = {"Option", "Box", "Arc", "Rc"}


def generic(ty: str) -> tuple[str, list[str]]:
    """`a::B<C, D>` -> ("a::B", ["C", "D"])."""
    ty = ty.strip().lstrip("&")
    m = re.match(r"([\w:]+)\s*<(.*)>$", ty, re.S)
    if not m:
        return ty, []
    return m.group(1), [a.strip() for _, a in split_top(*scan(m.group(2)))]


def rename(name: str, rule: str | None) -> str:
    if not rule or (rule == "snake_case" and name.islower()):
        return name
    words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", name) if "_" not in name else name.split("_")
    words = [w.lower() for w in words]
    if rule == "kebab-case":
        return "-".join(words)
    if rule == "camelCase":
        return words[0] + "".join(w.title() for w in words[1:])
    if rule == "lowercase":
        return "".join(words)
    if rule == "SCREAMING_SNAKE_CASE":
        return "_".join(words).upper()
    return "_".join(words)


def feature_of(attrs: str) -> str:
    m = re.search(r'cfg\(\s*feature\s*=\s*"([^"]+)"', attrs)
    return f"feature {m.group(1)}" if m else ""


class ConfigWalker:
    def __init__(self) -> None:
        self.index = Index()
        self.out: dict[str, Entry] = {}

    def emit(self, key: str, file: Path, line: int, note: str) -> None:
        self.out.setdefault(key, Entry(key, rel(file), line, note))

    def walk_type(self, ty: str, key: str, near: Path, line: int, note: str, seen: tuple) -> None:
        head, args = generic(ty)
        base = head.split("::")[-1]
        if base in WRAP and args:
            return self.walk_type(args[0], key, near, line, note, seen)
        if base in SEQ and args:
            return self.walk_type(args[0], key + "[]", near, line, note, seen)
        if base in MAP and len(args) == 2:
            return self.walk_type(args[1], key + ".<name>", near, line, note, seen)
        item = self.index.resolve(head, near)
        if item is None or item.name in self.index.manual or item.name in seen:
            return
        self.walk_item(item, key, note, seen + (item.name,))

    def walk_item(self, item: Item, key: str, note: str, seen: tuple) -> None:
        via = serde_attr(item.attrs, "try_from") or serde_attr(item.attrs, "from")
        if via:
            return self.walk_type(via, key, item.file, item.line, note, seen)
        rule = serde_attr(item.attrs, "rename_all")
        if item.kind == "struct":
            if item.tuple_body is not None:
                return self.walk_type(item.tuple_body, key, item.file, item.line, note, seen)
            transparent = serde_attr(item.attrs, "transparent") is not None
            self.walk_fields(item.members, item, key, rule, note, seen, transparent)
            return
        # enum: unit-only enums are a scalar value; payload variants add keys
        tagged = serde_attr(item.attrs, "untagged") is not None or serde_attr(item.attrs, "tag") is not None
        # Adjacent tagging nests each variant's payload under the content key.
        content = serde_attr(item.attrs, "content")
        tagged_key = (f"{key}.{content}" if key else content) if content else key
        # An internally or adjacently tagged enum adds its tag (and content) key.
        for attr in ("tag", "content"):
            name = serde_attr(item.attrs, attr)
            if name:
                self.emit(f"{key}.{name}" if key else name, item.file, item.line, note)
        for v in item.members:
            if serde_attr(v.attrs, "skip") is not None or serde_attr(v.attrs, "skip_deserializing") is not None:
                continue
            vname = serde_attr(v.attrs, "rename") or rename(v.name, rule)
            vkey = tagged_key if tagged else f"{key}.{vname}".lstrip(".")
            vnote = feature_of(v.attrs) or note
            if v.ty.startswith("{"):
                if not tagged:
                    self.emit(vkey, item.file, v.line, vnote)
                fields = member_fields(v.ty, item.file)
                for f in fields:
                    f.line = v.line
                self.walk_fields(fields, item, vkey, serde_attr(v.attrs, "rename_all"), vnote, seen, False)
            elif v.ty.startswith("("):
                inner = v.ty[1:-1].strip()
                if "," not in inner:
                    if not tagged:
                        self.emit(vkey, item.file, v.line, vnote)
                    self.walk_type(inner, vkey, item.file, v.line, vnote, seen)

    def walk_fields(self, fields, item, key, rule, note, seen, transparent) -> None:
        for f in fields:
            a = f.attrs
            if serde_attr(a, "skip") is not None or serde_attr(a, "skip_deserializing") is not None:
                continue
            fnote = feature_of(a) or note
            if transparent or serde_attr(a, "flatten") is not None:
                self.walk_type(f.ty, key, item.file, f.line, fnote, seen)
                continue
            name = serde_attr(a, "rename") or rename(f.name, rule)
            fkey = f"{key}.{name}" if key else name
            self.emit(fkey, item.file, f.line, fnote)
            if serde_attr(a, "with") is None and serde_attr(a, "deserialize_with") is None:
                self.walk_type(f.ty, fkey, item.file, f.line, fnote, seen)


def extract_config() -> list[Entry]:
    w = ConfigWalker()
    root = w.index.resolve("Config", SRC / "config/mod.rs")
    w.walk_item(root, "", "", ("Config",))
    # Retired keys still load (with a warning), so a user can still write them.
    sk = SRC / "config/strict_keys.rs"
    code, _ = scan(sk.read_text(encoding="utf-8"))
    for block, prefix in (("RETIRED_BACKEND_KEYS", "backends.<name>."), ("RETIRED_KEYS", "")):
        m = re.search(rf"const {block}\b[^=]*=\s*&\[", code)
        body = code[m.end() : code.index("];", m.end())]
        for t in re.finditer(r"\(\s*(&\[[^\]]*\]|\"[^\"]+\")", body):
            key = prefix + ".".join(re.findall(r'"([^"]+)"', t.group(1)))
            w.out.setdefault(key, Entry(key, rel(sk), line_of(code, m.end() + t.start()), "retired: loads with a warning"))
    return sorted(w.out.values(), key=lambda e: e.id)


# ── Surface: CLI ─────────────────────────────────────────────────────────────

CLAP = "Parser|Subcommand|Args"


def unwrap(ty: str) -> str:
    head, args = generic(ty)
    return unwrap(args[0]) if head.split("::")[-1] in WRAP | {"Vec"} and args else head


class CliWalker:
    def __init__(self, index: Index) -> None:
        self.index = index
        self.out: dict[str, Entry] = {}

    def emit(self, key: str, file: Path, line: int, note: str) -> None:
        self.out.setdefault(key, Entry(key, rel(file), line, note))

    def args(self, fields: list[Member], file: Path, line: int, prefix: str) -> None:
        for f in fields:
            a = f.attrs
            ln = f.line or line
            if attr_value(a, "command", "subcommand") is not None or attr_value(a, "clap", "subcommand") is not None:
                item = self.index.resolve(unwrap(f.ty), file, CLAP)
                if item:
                    self.subcommands(item, prefix)
                continue
            if attr_value(a, "command", "flatten") is not None or attr_value(a, "clap", "flatten") is not None:
                item = self.index.resolve(unwrap(f.ty), file, CLAP)
                if item:
                    self.args(item.members, item.file, item.line, prefix)
                continue
            long = attr_value(a, "arg", "long")
            short = attr_value(a, "arg", "short")
            if long is not None:
                flag = "--" + (long or f.name.replace("_", "-"))
            elif short is not None:
                flag = "-" + (short.strip("'") or f.name[0])
            else:
                flag = f"<{f.name.replace('_', '-')}>"
            notes = []
            if (env := attr_value(a, "arg", "env")) is not None:
                notes.append(f"env {env}")
            if attr_value(a, "arg", "global") == "true":
                notes.append("global")
            if attr_value(a, "arg", "hide") == "true":
                notes.append("hidden")
            self.emit(f"{prefix} {flag}", file, ln, ", ".join(notes))

    def subcommands(self, item: Item, prefix: str) -> None:
        for v in item.members:
            a = v.attrs
            if attr_value(a, "command", "skip") is not None:
                continue
            if attr_value(a, "command", "flatten") is not None:
                inner = self.index.resolve(unwrap(v.ty[1:-1]), item.file, CLAP)
                if inner:
                    self.subcommands(inner, prefix)
                continue
            name = attr_value(a, "command", "name") or rename(v.name, "kebab-case")
            key = f"{prefix} {name}"
            notes = [n for n in (feature_of(a), "hidden" if attr_value(a, "command", "hide") == "true" else "") if n]
            self.emit(key, item.file, v.line, ", ".join(notes))
            if v.ty.startswith("{"):
                self.args(member_fields(v.ty, item.file), item.file, v.line, key)
            elif v.ty.startswith("("):
                inner = self.index.resolve(unwrap(v.ty[1:-1]), item.file, CLAP)
                if inner is None:
                    continue
                if inner.kind == "enum":
                    self.subcommands(inner, key)
                else:
                    self.args(inner.members, inner.file, inner.line, key)


def extract_cli(index: Index | None = None) -> list[Entry]:
    w = CliWalker(index or Index())
    root = w.index.resolve("Cli", SRC / "cli/mod.rs", "Parser")
    w.emit("mcp-gateway", root.file, root.line, "")
    w.args(root.members, root.file, root.line, "mcp-gateway")
    return sorted(w.out.values(), key=lambda e: e.id)


# ── Surface: env ─────────────────────────────────────────────────────────────

ENV_RE = re.compile(r"MCP_GATEWAY_[A-Z0-9_]*")
# User-facing docs whose env names count as published surface.
ENV_DOC_GLOBS = (
    "README.md",
    "docs/*.md",
    "docs/runbooks/**/*",
    "docs/runtime/**/*",
    "docs/capabilities/**/*",
    "gateway.example.yaml",
    "examples/**/*",
    "deploy/**/*",
)
ENV_DOC_SKIP = re.compile(r"UPGRADING-|release-notes|CHANGELOG")


def extract_env() -> list[Entry]:
    out: dict[str, Entry] = {}
    for path in src_files():
        code, _ = prod_scan(path)
        for m in ENV_RE.finditer(code):
            name = m.group()
            if name == "MCP_GATEWAY_":
                name, note = "MCP_GATEWAY_<SECTION>__<KEY>", "config overlay: any gateway.yaml key"
            else:
                note = "read by the binary"
            out.setdefault(name, Entry(name, rel(path), line_of(code, m.start()), note))
    for glob in ENV_DOC_GLOBS:
        for path in sorted(ROOT.glob(glob)):
            if not path.is_file() or ENV_DOC_SKIP.search(path.name):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for m in ENV_RE.finditer(text):
                name = m.group()
                if name == "MCP_GATEWAY_":
                    continue
                note = "documented overlay spelling" if "__" in name else "documented only"
                out.setdefault(name, Entry(name, rel(path), line_of(text, m.start()), note))
    return sorted(out.values(), key=lambda e: e.id)


# ── Surface: routes ──────────────────────────────────────────────────────────


# Path-taking calls (`.route`, `.route_service`, `.nest`, `.nest_service`) that are not HTTP registrations: the continuation in-flight
# table's `route(key, now)`. Any other non-constant `.route(` becomes an item
# the inventory must classify, so a new listener path cannot slip past.
NOT_HTTP_ROUTES = {
    ("src/gateway/meta_mcp/chain_interim.rs", "&payload.hold_key"),
    ("src/gateway/meta_mcp/invoke/continuation.rs", "&payload.hold_key"),
    ("src/gateway/meta_mcp/task_confirmation.rs", "&payload.hold_key"),
    ("src/protocol/continuation/ledger/in_flight_lifetime.rs", "&key"),
}


def route_constants(code: str) -> list[tuple[str, str, int]]:
    """(NAME, path, line) for each `NAME = "path",` entry of `owned_routes!`."""
    return [
        (m.group(1), m.group(2), line_of(code, m.start()))
        for m in re.finditer(r"\b([A-Z][A-Z0-9_]*)\s*=\s*\"([^\"]+)\"", code)
    ]


def extract_routes() -> list[Entry]:
    path = SRC / "gateway/routes.rs"
    code, _ = scan(path.read_text(encoding="utf-8"))
    out = {}
    owned = set()
    for name, route, line in route_constants(code):
        owned.add(name)
        out[route] = Entry(route, rel(path), line, name)
    # A listener path that is not one of the owned constants: the webhook
    # receiver under `webhooks.base_path`, the backend OAuth callback listener.
    for p in src_files():
        code, _ = prod_scan(p)
        # A `routes::NAME` the table does not declare is an item nobody classified.
        for m in re.finditer(r"\broutes::([A-Z][A-Z0-9_]*)\b", code):
            if m.group(1) not in owned and m.group(1) != "OWNED":
                rid = f"unresolved routes::{m.group(1)} ({rel(p)})"
                out.setdefault(rid, Entry(rid, rel(p), line_of(code, m.start()), "not in routes.rs"))
        # Method calls take the path first; `Router::route(router, path, ..)` takes it second.
        calls = [(m, m.group(1)) for m in re.finditer(r"\.\s*(?:route|route_service|nest|nest_service)\s*\(\s*([^,]+?)\s*,", code)]
        calls += [(m, m.group(1)) for m in re.finditer(r"\bRouter\s*(?:::\s*<[^>]*>\s*)?::\s*(?:route|route_service|nest|nest_service)\s*\(\s*[^,]+?,\s*([^,]+?)\s*,", code)]
        for m, arg in calls:
            # Only a bare declared constant is already a row; any expression over one is not.
            if (re.fullmatch(r"routes::([A-Z][A-Z0-9_]*)", arg) and arg[8:] in owned) or (rel(p), arg) in NOT_HTTP_ROUTES:
                continue
            rid = f"dynamic {arg} ({rel(p)})"
            out.setdefault(rid, Entry(rid, rel(p), line_of(code, m.start()), "path from config"))
    return sorted(out.values(), key=lambda e: e.id)


# ── Surface: lib ─────────────────────────────────────────────────────────────


LIB_ITEM_RE = re.compile(
    r"^((?:#\[[^\n]*\]\s*)*)pub\s+(?:(?:const(?=\s+(?:async\s+|unsafe\s+|extern\s+\"\w+\"\s+)*fn\b)|async|unsafe|extern\s+\"\w+\")\s+)*"
    r"(mod|use|fn|const\s+fn|const|static|struct|enum|trait|type|union|extern\s+crate)\s+([^;{(=<]+)",
    re.M,
)


def extract_lib(path: Path | None = None) -> list[Entry]:
    # `#[macro_export]` puts a macro at the crate root from any module file.
    files = [path] if path else sorted(SRC.rglob("*.rs"))
    path = path or SRC / "lib.rs"
    code, mask = prod_scan(path)
    out = []
    for f in files:
        fcode = code if f == path else prod_scan(f)[0]
        for m in re.finditer(r"^#\[macro_export(?:\([^)]*\))?\][^\n]*\n(?:#\[[^\n]*\]\s*)*macro_rules!\s*(\w+)", fcode, re.M):
            out.append(Entry(f"mcp_gateway::{m.group(1)}!", rel(f), line_of(fcode, m.start()), "exported macro"))
    for m in LIB_ITEM_RE.finditer(code):
        kind, rest = m.group(2).split()[-1], " ".join(m.group(3).split())
        note = feature_of(m.group(1))
        if kind == "use":
            end = code.index(";", m.start())
            body = " ".join(code[m.end(2) : end].split())
            root, _, names = body.partition("{")
            for name in (names.rstrip("}").split(",") if names else [root.rsplit("::", 1)[-1]]):
                name = name.strip()
                if name:
                    out.append(Entry(f"mcp_gateway::{name}", rel(path), line_of(code, m.start(2)), f"re-export from {root.strip(' :')}"))
            continue
        # `extern crate a as b` exports `b`.
        name = rest.split(" as ")[-1].split(":")[0].strip()
        out.append(Entry(f"mcp_gateway::{name}", rel(path), line_of(code, m.start(2)), " ".join(x for x in (kind, note) if x)))
    return sorted(out, key=lambda e: e.id)


# ── The inventory doc ────────────────────────────────────────────────────────

EXTRACTORS = {
    "config": extract_config,
    "cli": extract_cli,
    "env": extract_env,
    "routes": extract_routes,
    "lib": extract_lib,
}


@dataclass
class Row:
    surface: str
    id: str
    cls: str
    migration: str
    defined: str
    lineno: int


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse_doc(text: str) -> list[Row]:
    """Rows of every `## Surface: <name>` table; columns found by header name."""
    rows, surface, header = [], None, None
    for n, line in enumerate(text.splitlines(), 1):
        h = re.match(r"##\s+Surface:\s*(\w+)", line)
        if h:
            surface, header = h.group(1), None
            continue
        if line.startswith("## "):
            surface = None
            continue
        if surface is None or not line.lstrip().startswith("|"):
            continue
        c = cells(line)
        if header is None:
            header = [x.lower() for x in c]
            continue
        if set("".join(c)) <= set("-: "):
            continue

        def get(name: str) -> str:
            i = header.index(name) if name in header else len(c)
            return c[i] if i < len(c) else ""

        item = re.sub(r"^`(.*)`$", r"\1", get("item"))
        rows.append(Row(surface, item, get("class"), get("migration"), get("defined at").strip("`"), n))
    return rows


def check(doc_text: str, extracted: dict[str, list[Entry]]) -> list[str]:
    """Every problem with the doc, one line each; empty when the doc is complete."""
    errors = []
    by_surface: dict[str, dict[str, Row]] = {s: {} for s in SURFACES}
    for r in parse_doc(doc_text):
        if r.surface not in by_surface:
            errors.append(f"line {r.lineno}: unknown surface {r.surface!r}")
            continue
        if r.id in by_surface[r.surface]:
            errors.append(f"line {r.lineno}: {r.surface} item {r.id!r} listed twice")
        by_surface[r.surface][r.id] = r
        if r.cls not in CLASSES:
            errors.append(f"line {r.lineno}: {r.id!r} has class {r.cls!r}, want one of {sorted(CLASSES)}")
        elif r.cls != "KEEP" and r.migration in {"", "-"}:
            errors.append(f"line {r.lineno}: {r.cls} item {r.id!r} has no migration story")
    for surface in sorted(set(extracted) - set(SURFACES)):
        errors.append(f"{surface}: extracted surface has no section in the doc's vocabulary")
    for surface in SURFACES:
        entries = extracted.get(surface)
        if not entries:
            # An extractor that finds nothing is broken, never "all classified".
            errors.append(f"{surface}: extractor returned no items")
            continue
        listed = by_surface[surface]
        for e in entries:
            r = listed.pop(e.id, None)
            if r is None:
                errors.append(f"{surface}: unclassified {e.id!r} ({e.file}:{e.line})")
            elif r.defined.split(":")[0] != e.file:
                errors.append(f"line {r.lineno}: {e.id!r} is defined in {e.file}, doc says {r.defined!r}")
        for r in listed.values():
            errors.append(f"line {r.lineno}: {surface} item {r.id!r} no longer exists in the code")
    return errors


def extract_all() -> dict[str, list[Entry]]:
    index = Index()
    out = {s: f() for s, f in EXTRACTORS.items() if s != "cli"}
    out["cli"] = extract_cli(index)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", choices=SURFACES, help="print one surface's extracted items")
    ap.add_argument("--doc", type=Path, default=DOC)
    ap.add_argument("--summary", action="store_true", help="print class counts per surface from the doc")
    args = ap.parse_args(argv)
    if args.summary:
        table: dict[str, dict[str, int]] = {}
        for r in parse_doc(args.doc.read_text(encoding="utf-8")):
            table.setdefault(r.surface, {}).setdefault(r.cls, 0)
            table[r.surface][r.cls] += 1
        print("surface  " + "  ".join(f"{c:>8}" for c in sorted(CLASSES)) + "     total")
        for surface in SURFACES:
            row = table.get(surface, {})
            print(f"{surface:<8} " + "  ".join(f"{row.get(c, 0):>8}" for c in sorted(CLASSES)) + f"  {sum(row.values()):>8}")
        return 0
    if args.list:
        for e in EXTRACTORS[args.list]():
            print(f"{e.id}\t{e.file}:{e.line}\t{e.note}")
        return 0
    extracted = extract_all()
    errors = check(args.doc.read_text(encoding="utf-8"), extracted)
    for line in errors:
        print(line, file=sys.stderr)
    counts = ", ".join(f"{s} {len(v)}" for s, v in extracted.items())
    if errors:
        print(f"surface inventory: {len(errors)} problem(s); extracted {counts}", file=sys.stderr)
        return 1
    print(f"surface inventory complete: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
