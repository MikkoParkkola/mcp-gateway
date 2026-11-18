#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shipped files use only KEEP CLI commands and flags, config keys and variables.

surface-4.0.md classes every CLI command and flag. A hidden (non-KEEP) one still
works, but a shipped file that passes it teaches users an item `--help` hides.
This check reads what users copy: the user docs, the examples, every deploy file
(Helm templates and rendered goldens, the Kubernetes base, compose, the systemd
unit, the launchd plist) and the Dockerfile. It fails on a non-KEEP command or
flag in a gateway command line, and on a non-KEEP `MCP_GATEWAY_` variable or
config key in a deploy file (surface_docs.py already covers docs and examples).

Lexical by design and stdlib only.

Usage:
  surface_shipped.py     scan the repository; exit 1 listing each finding
"""

from __future__ import annotations

import html
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import check_surface_inventory as inv
import surface_docs as sd

ROOT = inv.ROOT

# Inventory classes this check reports. STRAY is surface_docs' "not a key"
# verdict for a name the table does not list; a shipped file may name another
# tool's variable, and the fixture rows are a subset of the real table.
_REPORT = {"INTERNAL", "AUTO", "REMOVE"}
_READER_SUFFIXES = {".md", ".yaml", ".yml", ".tpl", ".json", ".txt", ".sh", ".service", ".plist"}
_OPS = frozenset("|;&><")
_SHELLS = {"sh", "bash"}
# Dashes and dots: a compose name (`b-x:`, `other.service:`) is a key, and a
# shallower one closes the service open above it.
_KEY = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)\s*:(?:\s*(.*))?$")
_ITEM = re.compile(r"^(\s*)-\s+\S")
_EXEC = re.compile(r"^(ENTRYPOINT|CMD)\s+(\[.*\])\s*$")
_PLIST_STRING = re.compile(r"<string>(.*?)</string>")
_YAML_HIT = re.compile(
    r"^(?P<file>.+):(?P<line>\d+): (?P<item>.+) is (?P<cls>INTERNAL|AUTO|REMOVE) in surface-4\.0\.md"
)
_FLAG_BODY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*\Z")
_ARG_TOKEN = re.compile(r"<[^>\s]+>\Z")


@dataclass(frozen=True)
class Hit:
    """One finding: where, the item's class, and the item as the table spells it."""

    file: str
    line: int
    cls: str
    item: str
    # The full command path of the invocation the hit came from (for the allow
    # table's ancestor rule); empty for a variable or config key.
    invocation: tuple[str, ...] = ()


@dataclass
class CliTable:
    """The cli rows of surface-4.0.md: commands by path, flags by (path, flag)."""

    commands: dict[tuple[str, ...], str] = field(default_factory=dict)
    flags: dict[tuple[tuple[str, ...], str], str] = field(default_factory=dict)

    @classmethod
    def from_doc(cls, text: str) -> CliTable:
        """Cli rows. A row whose last token is `-x`/`--x` or `<ARG>` is a flag
        of the path before it; every other row is a command path."""
        out = cls()
        for row in inv.parse_doc(text):
            if row.surface != "cli" or not row.id:
                continue
            parts = row.id.split()
            last = parts[-1]
            if len(parts) >= 2 and (_flag_name(last) or _ARG_TOKEN.match(last)):
                name = _flag_name(last) or last
                out.flags[(tuple(parts[:-1]), name)] = row.cls
            else:
                out.commands[tuple(parts)] = row.cls
        return out


def _flag_name(token: str) -> str | None:
    """`--x=v` and `-x=v` become `--x` and `-x`. `--` is end-of-flags, not a flag."""
    if token == "--" or not token.startswith("-"):
        return None
    body = token[2:] if token.startswith("--") else token[1:]
    body = body.split("=", 1)[0]
    if not body or not _FLAG_BODY.match(body):
        return None
    return ("--" if token.startswith("--") else "-") + body


def _is_gateway_bin(token: str) -> bool:
    """Last path part, with `:tag` and `@digest` removed, is the gateway binary."""
    if not token or token.startswith("-") or any(c in token for c in _OPS):
        return False
    base = token.rsplit("/", 1)[-1].split("@", 1)[0].split(":", 1)[0]
    return base == "mcp-gateway"


def _gateway_image(value: str | None) -> bool:
    """Image ref basename, or the chart's `mcp-gateway.image` include."""
    if not value:
        return False
    if "mcp-gateway.image" in value:
        return True
    token = value.strip().strip("\"'").split()
    return bool(token) and _is_gateway_bin(token[0].strip("\"'"))


def _lookup_flag(table: CliTable, path: tuple[str, ...], flag: str) -> tuple[str, str] | None:
    """(class, item id) of `flag` on `path` or the nearest parent that lists it."""
    parts = path
    while parts:
        cls = table.flags.get((parts, flag))
        if cls:
            return cls, " ".join((*parts, flag))
        parts = parts[:-1]
    return None


def _is_operator(token: str) -> bool:
    return bool(token) and all(ch in _OPS for ch in token)


def _strip_marker(text: str) -> str:
    """Drop one leading `#`, `$` or `>` prompt or comment marker."""
    i = 0
    while i < len(text) and text[i] in " \t":
        i += 1
    if i < len(text) and text[i] in "#$>":
        i += 1
        if i < len(text) and text[i] == " ":
            i += 1
        return text[i:]
    return text


def _groups(lines: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """Split on trailing backslashes. Each piece keeps its source line."""
    groups: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] = []
    for item in lines:
        cur.append(item)
        if not item[1].rstrip().endswith("\\"):
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)
    return groups


def _cut_shell_comment(text: str) -> str:
    """Drop a `#` comment outside quotes: at the line start or after whitespace,
    as the shell reads one (`x#y` is one word). An apostrophe in the comment
    must not reach the lexer: an unbalanced quote drops the whole line."""
    quote: str | None = None
    i = 0
    at_word_start = True
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\":
            i += 2
            at_word_start = False
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            at_word_start = False
            continue
        if ch == "#" and at_word_start:
            return text[:i].rstrip()
        at_word_start = ch in " \t"
        i += 1
    return text


def _tokenize(group: list[tuple[int, str]]) -> list[tuple[str, int]]:
    """Posix-tokenize one continuation group. Punctuation (`|;&><`) is its own token.

    A trailing backslash is removed before lexing so it joins the next physical
    line, and each token is stamped with the line its first character came from.
    A `#` outside quotes is a comment, cut before lexing.
    """
    chars: list[tuple[str, int]] = []
    for index, (lineno, raw) in enumerate(group):
        # A backtick bounds a command: prose wraps one in it (`run `mcp-gateway
        # --host``), and shell substitutes one, so the words after it are not its.
        text = _cut_shell_comment(_strip_marker(raw)).replace("`", " ; ")
        if text.rstrip().endswith("\\"):
            text = text.rstrip()[:-1]
        for ch in text:
            chars.append((ch, lineno))
        if index != len(group) - 1:
            chars.append((" ", lineno))
    if not chars:
        return []
    text = "".join(ch for ch, _ in chars)
    lexer = shlex.shlex(text, posix=True, punctuation_chars="();<>|&")
    lexer.commenters = ""
    # whitespace_split keeps `:` `@` `/` inside a word (`mcp-gateway:4.0.0`).
    # punctuation_chars still breaks the stream on shell operators.
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    out: list[tuple[str, int]] = []
    pos = 0
    for token in tokens:
        idx = text.find(token, pos)
        if idx < 0:
            idx = pos
        out.append((token, chars[min(idx, len(chars) - 1)][1]))
        pos = idx + max(len(token), 1)
    return out


def _walk(
    tokens: list[tuple[str, int]], start: int, table: CliTable
) -> tuple[list[tuple[int, str, str]], tuple[str, ...], int]:
    """Walk one gateway invocation starting at `tokens[start]`.

    Returns (hits as line/class/item, the full command path, the index to resume).
    A child command extends the path, including right after a flag, until the
    first positional: a token that is neither a flag, a child, nor the value of
    a flag written without `=`. Flags after a positional still count. `--` ends
    flag reading; a shell operator ends the invocation.
    """
    path = ("mcp-gateway",)
    found: list[tuple[int, str, str]] = []
    taking = False
    flags_done = False
    extending = True
    i = start
    n = len(tokens)
    while i < n:
        token, line = tokens[i]
        if _is_operator(token):
            return found, path, i + 1
        if token == "--":
            flags_done = True
            taking = False
            i += 1
            continue
        if i > start and not taking and _is_gateway_bin(token):
            # Another gateway binary (not a flag's value) starts its own invocation (the caller
            # resumes here): `kubectl -n mcp-gateway exec x -- mcp-gateway ...`.
            return found, path, i
        flag = None if flags_done else _flag_name(token)
        if flag:
            got = _lookup_flag(table, path, flag)
            if got and got[0] in _REPORT:
                found.append((line, got[0], got[1]))
            taking = "=" not in token
            i += 1
            continue
        child = path + (token,)
        if extending and child in table.commands:
            path = child
            cls = table.commands[path]
            if cls in _REPORT:
                found.append((line, cls, " ".join(path)))
            taking = False
            i += 1
            continue
        if taking and not flags_done:
            taking = False
            i += 1
            continue
        extending = False
        i += 1
    return found, path, n


def command_hits(
    tokens: list[tuple[str, int]], file: str, table: CliTable, implied: bool = False
) -> list[Hit]:
    """Hits in one token stream (token, source line). A gateway command starts at
    a token whose last path part, without `:tag` or `@digest`, is `mcp-gateway`,
    or at the first token when `implied` (arguments to the image ENTRYPOINT)."""
    hits: list[Hit] = []

    def take(found: list[tuple[int, str, str]], invocation: tuple[str, ...], binary_line: int | None) -> None:
        root = table.commands.get(("mcp-gateway",))
        if binary_line is not None and root in _REPORT:
            hits.append(Hit(file, binary_line, root, "mcp-gateway", invocation))
        for line, cls, item in found:
            hits.append(Hit(file, line, cls, item, invocation))

    i = 0
    n = len(tokens)
    if implied and tokens:
        # The arguments of the image ENTRYPOINT; a later gateway binary in them
        # starts its own invocation, scanned by the loop below.
        found, invocation, i = _walk(tokens, 0, table)
        take(found, invocation, None)
    while i < n:
        token, line = tokens[i]
        if _is_gateway_bin(token):
            found, invocation, nxt = _walk(tokens, i + 1, table)
            if nxt <= i:
                nxt = i + 1
            take(found, invocation, line)
            i = nxt
            continue
        # A quoted command line is one token (`sh -c "mcp-gateway ..."`, a JSON or
        # prose quote): scan its words as a command of their own.
        words = token.split()
        if len(words) > 1 and _is_gateway_bin(words[0]):
            hits.extend(command_hits(_tokenize([(line, token)]), file, table))
        i += 1
    return hits


def _shell_hits(lines: list[tuple[int, str]], file: str, table: CliTable) -> list[Hit]:
    hits: list[Hit] = []
    for group in _groups(lines):
        hits += command_hits(_tokenize(group), file, table, implied=False)
    return hits


def _scan_markdown(file: str, text: str, table: CliTable) -> list[Hit]:
    hits: list[Hit] = []
    blocks, inside = sd.fences(text)
    for lang, body, line0 in blocks:
        if lang in {"yaml", "yml"}:
            for hit in _scan_yaml_commands(file, body, table):
                hits.append(Hit(file, hit.line + line0 - 1, hit.cls, hit.item, hit.invocation))
            continue
        indexed = [(line0 + i, line) for i, line in enumerate(body.splitlines())]
        hits += _shell_hits(indexed, file, table)
    for n, line in enumerate(text.splitlines(), 1):
        if n in inside:
            continue
        for span in sd.SPAN.finditer(line):
            hits += command_hits(_tokenize([(n, span.group(1))]), file, table, implied=False)
    return hits


def _cut_unquoted(text: str, marker: str) -> str:
    """Text up to `marker` when it sits outside quotes. Quotes keep their contents."""
    quote: str | None = None
    escape = False
    for i, ch in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif ch == "\\" and quote == '"':
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == marker and (marker != "#" or i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text


def _unquote(value: str) -> str:
    value = _cut_unquoted(value.strip(), "#")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _flow_items(lines: list[str], start: int) -> list[tuple[str, int]]:
    """Items of a `[...]` list that may span lines, each with its source line."""
    items: list[tuple[str, int]] = []
    buf: list[str] = []
    buf_line = start + 1
    quote: str | None = None
    escape = False
    depth = 0
    begun = False

    def finish() -> None:
        nonlocal buf, buf_line
        text = "".join(buf).strip()
        if text:
            items.append((text, buf_line))
        buf = []

    for i in range(start, len(lines)):
        line = lines[i]
        j = line.find("[") if i == start else 0
        if i == start and j < 0:
            return []
        while j < len(line):
            ch = line[j]
            if quote:
                if escape:
                    buf.append(ch)
                    escape = False
                elif ch == "\\" and quote == '"':
                    escape = True
                elif ch == quote:
                    quote = None
                else:
                    buf.append(ch)
                j += 1
                continue
            if ch in "\"'":
                if not "".join(buf).strip():
                    buf = []
                    buf_line = i + 1
                quote = ch
                j += 1
                continue
            if ch == "[":
                depth += 1
                begun = True
                if depth > 1:
                    buf.append(ch)
                j += 1
                continue
            if ch == "]" and begun:
                depth -= 1
                if depth == 0:
                    finish()
                    return items
                buf.append(ch)
                j += 1
                continue
            if ch == "," and depth == 1:
                finish()
                buf_line = i + 1
                j += 1
                continue
            if ch == "#" and (j == 0 or line[j - 1] in " \t"):
                break
            if ch in " \t" and not "".join(buf).strip():
                j += 1
                continue
            if not buf:
                buf_line = i + 1
            buf.append(ch)
            j += 1
    finish()
    return items


def _block_items(lines: list[str], start: int, key_indent: int) -> list[tuple[str, int]]:
    """Block sequence under `key`, including items at the key's own column.

    A sibling key at that column ends the sequence. A deeper non-item does too.
    """
    items: list[tuple[str, int]] = []
    i = start + 1
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("{{"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        item = re.match(r"\s*-\s*(.*)$", line)
        if indent < key_indent or (indent == key_indent and not item):
            break
        if not item:
            break
        items.append((_unquote(item.group(1)), i + 1))
        i += 1
    return items


def _block_text(lines: list[str], start: int, key_indent: int) -> list[tuple[int, str]]:
    body: list[tuple[int, str]] = []
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= key_indent:
                break
        body.append((i + 1, line))
        i += 1
    return body


@dataclass
class _Value:
    kind: str  # "list" or "text"
    items: list[tuple[str, int]] = field(default_factory=list)
    lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class _Container:
    image: str | None = None
    command: _Value | None = None
    args: _Value | None = None
    key_indent: int = 0


def _value_at(lines: list[str], idx: int, raw: str, key_indent: int) -> _Value:
    val = raw.strip()
    if val.startswith("["):
        return _Value("list", items=_flow_items(lines, idx))
    # `"" in "|>"` is true, so an empty value must be tested before the prefix.
    if val.startswith(("|", ">")):
        return _Value("text", lines=_block_text(lines, idx, key_indent))
    if val == "":
        return _Value("list", items=_block_items(lines, idx, key_indent))
    return _Value("text", lines=[(idx + 1, _unquote(val))])


def _transparent(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#") or stripped.startswith("{{")


def _note_key(
    found: list[_Container],
    cur: _Container | None,
    lines: list[str],
    idx: int,
    indent: int,
    name: str,
    raw: str,
) -> _Container | None:
    """Record one mapping key. A shallower key closes the open mapping."""
    if cur and indent < cur.key_indent:
        found.append(cur)
        cur = None
    if name not in {"image", "command", "args"}:
        return cur
    slot = "image" if name == "image" else name
    if cur is None or indent != cur.key_indent or getattr(cur, slot) is not None:
        if cur:
            found.append(cur)
        cur = _Container(key_indent=indent)
    if name == "image":
        cur.image = raw.strip()
    else:
        setattr(cur, name, _value_at(lines, idx, raw, indent))
    return cur


def _containers(lines: list[str]) -> list[_Container]:
    """Mappings that carry image, command or args, grouped by key indent.

    A shallower line (the next list item, the next service) closes the mapping.
    `- image:` is that mapping's first key, at the key's column, not the dash.
    Keys may arrive in any order, so args above image still see the image.
    """
    found: list[_Container] = []
    cur: _Container | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if _transparent(line):
            i += 1
            continue
        item = _ITEM.match(line)
        if item:
            indent = len(item.group(1))
            if cur and indent < cur.key_indent:
                found.append(cur)
                cur = None
            dash = re.match(r"^(\s*)-\s+", line)
            key = _KEY.match(line[dash.end() :]) if dash else None
            if key:
                cur = _note_key(
                    found, cur, lines, i, dash.end() + len(key.group(1)), key.group(2), key.group(3) or ""
                )
            i += 1
            continue
        key = _KEY.match(line)
        if not key:
            i += 1
            continue
        cur = _note_key(found, cur, lines, i, len(key.group(1)), key.group(2), key.group(3) or "")
        i += 1
    if cur:
        found.append(cur)
    return found


def _is_shell(token: str) -> bool:
    base = token.rsplit("/", 1)[-1]
    return base in _SHELLS


def _scan_argv(value: _Value, image_gateway: bool, file: str, table: CliTable) -> list[Hit]:
    if value.kind == "text":
        tokens = _tokenize(value.lines)
        has_bin = any(_is_gateway_bin(token) for token, _ in tokens)
        return command_hits(tokens, file, table, implied=image_gateway and not has_bin)
    items = value.items
    if len(items) >= 3 and _is_shell(items[0][0]) and items[1][0] == "-c":
        script, line = items[2]
        return command_hits(_tokenize([(line, script)]), file, table, implied=False)
    if items and _is_gateway_bin(items[0][0]):
        return command_hits(items, file, table, implied=False)
    if image_gateway:
        return command_hits(items, file, table, implied=True)
    return command_hits(items, file, table, implied=False)


def _scan_yaml_commands(file: str, text: str, table: CliTable) -> list[Hit]:
    lines = text.splitlines()
    hits: list[Hit] = []
    comments = [(n, line) for n, line in enumerate(lines, 1) if line.lstrip().startswith("#")]
    # Comment runs only: a code line between two comments is not a continuation.
    run: list[tuple[int, str]] = []
    prev = 0
    for n, line in comments:
        if run and n != prev + 1:
            hits += _shell_hits(run, file, table)
            run = []
        run.append((n, line))
        prev = n
    if run:
        hits += _shell_hits(run, file, table)
    for ctr in _containers(lines):
        image_gateway = _gateway_image(ctr.image)
        if ctr.command and ctr.args:
            merged = _Value(
                "list",
                items=(ctr.command.items + ctr.args.items)
                if ctr.command.kind == "list" and ctr.args.kind == "list"
                else [],
            )
            if ctr.command.kind == "list" and ctr.args.kind == "list":
                hits += _scan_argv(merged, image_gateway, file, table)
            else:
                hits += _scan_argv(ctr.command, image_gateway, file, table)
                hits += _scan_argv(ctr.args, image_gateway, file, table)
        elif ctr.command:
            hits += _scan_argv(ctr.command, image_gateway, file, table)
        elif ctr.args:
            hits += _scan_argv(ctr.args, image_gateway, file, table)
    return hits


def _scan_config(file: str, text: str, rows: sd.Rows) -> list[Hit]:
    """A ConfigMap's embedded `gateway.yaml` block, at the block's line offset."""
    body, line0 = sd.rendered_config(text)
    if not body or not line0:
        return []
    hits: list[Hit] = []
    for msg in sd.yaml_errors(body, file, rows, line0, whole_file=True):
        got = _YAML_HIT.match(msg)
        if got:
            hits.append(Hit(got.group("file"), int(got.group("line")), got.group("cls"), got.group("item")))
    return hits


def _joined(group: list[tuple[int, str]]) -> str:
    """One Dockerfile instruction: a trailing backslash joins the next physical line."""
    parts: list[str] = []
    last = len(group) - 1
    for i, (_n, raw) in enumerate(group):
        text = raw.rstrip()
        if i != last and text.endswith("\\"):
            text = text[:-1]
        parts.append(text)
    return "".join(parts).strip()


def _exec_items(blob: str, group: list[tuple[int, str]]) -> list[tuple[str, int]] | None:
    """Exec-form array items, each stamped with the physical line it is written on."""
    try:
        arr = json.loads(blob)
    except json.JSONDecodeError:
        return None
    if not isinstance(arr, list) or not arr or not all(isinstance(item, str) for item in arr):
        return None
    found: list[tuple[str, int]] = []
    line_i, col = 0, 0
    for item in arr:
        needle = json.dumps(item)
        placed = False
        while line_i < len(group):
            pos = group[line_i][1].find(needle, col)
            if pos >= 0:
                found.append((item, group[line_i][0]))
                col = pos + len(needle)
                placed = True
                break
            line_i += 1
            col = 0
        if not placed:
            found.append((item, group[0][0]))
    return found


def _hits_exec(
    tokens: list[tuple[str, int]], kind: str, entry_gateway: bool, file: str, table: CliTable
) -> list[Hit]:
    """ENTRYPOINT/CMD exec form. `sh -c` is the script. The stage's last
    ENTRYPOINT decides whether a CMD array is arguments of the gateway."""
    if len(tokens) >= 3 and _is_shell(tokens[0][0]) and tokens[1][0] == "-c":
        script, line = tokens[2]
        return command_hits(_tokenize([(line, script)]), file, table, implied=False)
    if kind == "CMD":
        starts = bool(tokens) and _is_gateway_bin(tokens[0][0])
        return command_hits(tokens, file, table, implied=entry_gateway and not starts)
    return command_hits(tokens, file, table, implied=False)


def _scan_dockerfile(file: str, text: str, table: CliTable) -> list[Hit]:
    indexed = [(n, line) for n, line in enumerate(text.splitlines(), 1)]
    # kind, source lines, exec-form tokens (None when the instruction is not exec form).
    logical: list[tuple[str, list[tuple[int, str]], list[tuple[str, int]] | None]] = []
    for group in _groups(indexed):
        got = _EXEC.match(_joined(group))
        items = _exec_items(got.group(2), group) if got else None
        if got and items:
            logical.append((got.group(1), group, items))
        else:
            logical.append(("OTHER", group, None))
    stages: list[list[tuple[str, list[tuple[int, str]], list[tuple[str, int]] | None]]] = [[]]
    for kind, group, items in logical:
        if kind == "OTHER" and re.match(r"FROM\b", group[0][1].strip()):
            if stages[-1]:
                stages.append([])
        stages[-1].append((kind, group, items))
    hits: list[Hit] = []
    for stage in stages:
        entry_gateway = False
        for kind, group, items in stage:
            if kind == "ENTRYPOINT":
                entry_gateway = bool(items) and _is_gateway_bin(items[0][0])
            elif kind == "OTHER" and re.match(r"ENTRYPOINT\b", group[0][1].strip()):
                # Shell form runs through `sh -c`, which ignores CMD.
                entry_gateway = False
        for kind, group, items in stage:
            if items is not None and kind in {"ENTRYPOINT", "CMD"}:
                hits += _hits_exec(items, kind, entry_gateway, file, table)
            else:
                hits += command_hits(_tokenize(group), file, table, implied=False)
    return hits


_SYSTEMD_EXEC = re.compile(r"(ExecStartPre|ExecStartPost|ExecStart|ExecReload|ExecStopPost|ExecStop|ExecCondition)\s*=(.*)$")
# systemd exec prefixes, any combination, sit in front of the executable path.
_EXEC_PREFIX = re.compile(r"^[-@+!]+")


def _scan_systemd(file: str, text: str, table: CliTable) -> list[Hit]:
    lines = text.splitlines()
    hits: list[Hit] = []
    i = 0
    while i < len(lines):
        got = _SYSTEMD_EXEC.match(lines[i].strip())
        if not got:
            i += 1
            continue
        parts = [(i + 1, got.group(2))]
        while parts[-1][1].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            parts.append((i + 1, lines[i].strip()))
        tokens = _tokenize(parts)
        if tokens:
            path, line = tokens[0]
            stripped = _EXEC_PREFIX.sub("", path)
            if stripped and stripped != path:
                tokens = [(stripped, line), *tokens[1:]]
        hits += command_hits(tokens, file, table, implied=False)
        i += 1
    return hits


def _scan_plist(file: str, text: str, table: CliTable) -> list[Hit]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if "<key>ProgramArguments</key>" in line), None)
    if start is None:
        return []
    items: list[tuple[str, int]] = []
    in_array = False
    for i in range(start, len(lines)):
        line = lines[i]
        if "<array>" in line:
            in_array = True
            continue
        if not in_array:
            continue
        if "</array>" in line:
            break
        got = _PLIST_STRING.search(line)
        if got:
            items.append((html.unescape(got.group(1)), i + 1))
    return command_hits(items, file, table, implied=False)


_JSON_ESC = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _json_strings(text: str) -> list[tuple[int, str]]:
    """Decoded JSON strings, each stamped with the line of its opening quote."""
    out: list[tuple[int, str]] = []
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch != '"':
            i += 1
            continue
        start = line
        i += 1
        buf: list[str] = []
        closed = False
        while i < n:
            c = text[i]
            if c == "\\":
                i += 1
                if i >= n:
                    break
                esc = text[i]
                if esc in _JSON_ESC:
                    buf.append(_JSON_ESC[esc])
                elif esc == "u" and i + 4 < n:
                    try:
                        buf.append(chr(int(text[i + 1 : i + 5], 16)))
                        i += 4
                    except ValueError:
                        buf.append(esc)
                else:
                    buf.append(esc)
                i += 1
                continue
            if c == "\n":
                line += 1
            if c == '"':
                i += 1
                closed = True
                break
            buf.append(c)
            i += 1
        if closed:
            out.append((start, "".join(buf)))
    return out


def _scan_json(file: str, text: str, table: CliTable) -> list[Hit]:
    """Command hits in decoded string values. The raw file is not shell-lexed:
    a quoted command is one JSON string, not a token stream."""
    hits: list[Hit] = []
    for line, value in _json_strings(text):
        hits += _shell_hits([(line, value)], file, table)
    return hits


def _scan_env(file: str, text: str, rows: sd.Rows) -> list[Hit]:
    hits: list[Hit] = []
    for n, line in enumerate(text.splitlines(), 1):
        for got in sd.ENV.finditer(line):
            # `MCP_GATEWAY_<SECTION>` is a placeholder. `</key>` is a plist close.
            if line[got.end() :].startswith("<") and not line[got.end() :].startswith("</"):
                continue
            hit = sd.env_hit(got.group(), rows)
            if hit and hit[0] in _REPORT:
                hits.append(Hit(file, n, hit[0], hit[1]))
    return hits


def _env_scope(file: str) -> bool:
    name = Path(file).name
    return (
        name == "Dockerfile"
        or file.startswith("deploy/")
        or file.startswith("tests/fixtures/helm-golden/")
    )


def scan_text(file: str, text: str, table: CliTable, rows: sd.Rows) -> list[Hit]:
    """Every hit in one shipped file, read by the reader its name selects."""
    suffix = Path(file).suffix.lower()
    name = Path(file).name
    hits: list[Hit] = []
    if name == "Dockerfile":
        hits += _scan_dockerfile(file, text, table)
    elif suffix == ".md":
        hits += _scan_markdown(file, text, table)
    elif suffix in {".yaml", ".yml"}:
        hits += _scan_yaml_commands(file, text, table)
        hits += _scan_config(file, text, rows)
    elif suffix == ".json":
        hits += _scan_json(file, text, table)
    elif suffix in {".tpl", ".txt", ".sh"}:
        indexed = [(n, line) for n, line in enumerate(text.splitlines(), 1)]
        hits += _shell_hits(indexed, file, table)
    elif suffix == ".service":
        hits += _scan_systemd(file, text, table)
    elif suffix == ".plist":
        hits += _scan_plist(file, text, table)
    if _env_scope(file):
        hits += _scan_env(file, text, rows)
    return hits


# A command entry covers its command, everything under it and, within an
# invocation that reaches it, its ancestors; only while the command is non-KEEP,
# and only the ids in its reviewed snapshot. A variable entry covers that name in
# that file. Each entry needs a reason saying why the page cannot drop the mention;
# every new entry is shown to a review seat.
ALLOWED: dict[tuple[str, str], tuple[str, frozenset[str]]] = {
    ("docs/catalog_trust_lab.md", "mcp-gateway trust lab"): (
        "the certification lab's reference for catalogue maintainers and CI; the hidden command is its only interface, so the page cannot drop it without dropping itself",
        frozenset({
            "mcp-gateway trust",
            "mcp-gateway trust lab",
            "mcp-gateway trust lab evaluate",
            "mcp-gateway trust lab evaluate --active-fixtures",
            "mcp-gateway trust lab evaluate --baseline",
            "mcp-gateway trust lab evaluate --baseline-id",
            "mcp-gateway trust lab evaluate --baseline-registry",
            "mcp-gateway trust lab evaluate --capabilities",
            "mcp-gateway trust lab evaluate --enforce",
            "mcp-gateway trust lab evaluate --execute-active-fixtures",
            "mcp-gateway trust lab evaluate --format",
            "mcp-gateway trust lab evaluate --runtime-image",
            "mcp-gateway trust lab evaluate --runtime-provider-plan",
            "mcp-gateway trust lab evaluate --update-baseline-registry",
            "mcp-gateway trust lab evaluate --write-baseline",
        }),
    ),
    ("docs/trustcard.md", "mcp-gateway trust"): (
        "the TrustCard reference for catalogue maintainers; the hidden command is its only interface, so the page cannot drop it without dropping itself",
        frozenset({
            "mcp-gateway trust",
            "mcp-gateway trust generate",
            "mcp-gateway trust generate --capabilities",
            "mcp-gateway trust generate --format",
            "mcp-gateway trust inspect",
            "mcp-gateway trust inspect --capabilities",
            "mcp-gateway trust validate",
            "mcp-gateway trust validate --capabilities",
            "mcp-gateway trust validate --file",
            "mcp-gateway trust validate --format",
            "mcp-gateway trust validate --strict",
        }),
    ),
    ("docs/adaptive_ranking.md", "mcp-gateway ranking"): (
        "the adaptive ranker's offline evaluation for developers; the page documents that hidden tool and has no other route to describe",
        frozenset({
            "mcp-gateway ranking",
            "mcp-gateway ranking eval",
            "mcp-gateway ranking eval --format",
        }),
    ),
    ("deploy/kubernetes/enterprise-alpha/README.md", "mcp-gateway kubernetes"): (
        "the enterprise-alpha controller's own package README, where surface-4.0.md moved its docs; the controller is that command",
        frozenset({
            "mcp-gateway kubernetes",
            "mcp-gateway kubernetes apply-plan",
            "mcp-gateway kubernetes apply-plan --execute",
            "mcp-gateway kubernetes apply-plan --format",
            "mcp-gateway kubernetes apply-plan --namespace",
            "mcp-gateway kubernetes controller",
            "mcp-gateway kubernetes controller --cycles",
            "mcp-gateway kubernetes controller --format",
            "mcp-gateway kubernetes controller --interval-seconds",
            "mcp-gateway kubernetes controller --namespace",
            "mcp-gateway kubernetes plan",
            "mcp-gateway kubernetes plan --format",
            "mcp-gateway kubernetes plan --namespace",
        }),
    ),
    ("deploy/helm/mcp-gateway/templates/_helpers.tpl", "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW"): (
        "the chart's extraEnv guard must name the one CLI-owned variable it lets through (the operator's measurement window); the guard is code, not prose",
        frozenset({
            "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW",
        }),
    ),
}


def _command_entry(entry_id: str, table: CliTable) -> tuple[str, ...] | None:
    parts = tuple(entry_id.split())
    if parts in table.commands:
        return parts
    return None


def _item_path(item: str) -> tuple[str, ...]:
    parts = item.split()
    if parts and (_flag_name(parts[-1]) or _ARG_TOKEN.match(parts[-1])):
        parts = parts[:-1]
    return tuple(parts)


def _covers(hit: Hit, cmd: tuple[str, ...]) -> bool:
    """The command, what is under it, or an ancestor of an invocation that reaches it."""
    path = _item_path(hit.item)
    if not path:
        return False
    if path[: len(cmd)] == cmd:
        return True
    if len(path) < len(cmd) and cmd[: len(path)] == path:
        inv_path = hit.invocation
        return len(inv_path) >= len(cmd) and inv_path[: len(cmd)] == cmd
    return False


def apply_allowed(hits: list[Hit], allowed: dict, table: CliTable) -> tuple[list[Hit], list[str]]:
    """(hits not covered, stale-entry errors)."""
    covered = [False] * len(hits)
    used: set[tuple[str, str]] = set()
    present: dict[str, set[str]] = {}
    for hit in hits:
        present.setdefault(hit.file, set()).add(hit.item)
    for (fname, entry_id), (_reason, snapshot) in allowed.items():
        snap = snapshot or frozenset()
        cmd = _command_entry(entry_id, table)
        if cmd is not None:
            cls = table.commands.get(cmd)
            if cls not in _REPORT:
                continue
            for i, hit in enumerate(hits):
                if hit.file == fname and hit.item in snap and _covers(hit, cmd):
                    covered[i] = True
                    used.add((fname, entry_id))
            continue
        for i, hit in enumerate(hits):
            if hit.file == fname and (hit.item == entry_id or hit.item in snap):
                covered[i] = True
                used.add((fname, entry_id))
    missing: dict[tuple[str, str], str] = {}
    for key, (_reason, snapshot) in allowed.items():
        fname, _entry_id = key
        if key not in used:
            missing[key] = ""
        have = present.get(fname, set())
        for sid in snapshot or ():
            if sid not in have:
                missing[(fname, sid)] = ""
    kept = [hit for hit, done in zip(hits, covered) if not done]
    return kept, sd.stale_allowed(missing, set())


# Tracked deploy files that are not shipped configuration, each with its reason.
# Exact names: a glob would hide a new file of the same kind, which is the miss
# this list exists to make fail. Smoke scripts need no reader; they are not scanned.
NOT_SHIPPED: dict[str, str] = {
    "deploy/kubernetes/enterprise-alpha/scripts/kind-smoke.sh":
        "kind smoke script, test tooling, not configuration a user copies",
    "deploy/kubernetes/enterprise-alpha/scripts/kind-rollback-smoke.sh":
        "kind smoke script, test tooling, not configuration a user copies",
    "deploy/helm/mcp-gateway-crds/crds/mcpgateway.io.yaml":
        "CRD manifest, not a gateway command line or config a user copies",
    "deploy/kubernetes/enterprise-alpha/crds/mcpgateway.io.yaml":
        "CRD manifest, not a gateway command line or config a user copies",
    "deploy/prometheus/mcp-gateway-alerts.yml":
        "prometheus rules, not gateway configuration",
    "deploy/prometheus/mcp-gateway-alerts-test.yml":
        "prometheus rules test fixture, not gateway configuration",
}


def _selected(rel: str, user_docs: set[str]) -> bool:
    if rel in NOT_SHIPPED:
        return False
    if Path(rel).name == "Dockerfile" or rel.startswith("deploy/"):
        return True
    if rel.startswith("tests/fixtures/helm-golden/") and Path(rel).suffix in {".yaml", ".yml"}:
        return True
    return rel in user_docs


def _has_reader(rel: str) -> bool:
    if Path(rel).name == "Dockerfile":
        return True
    return Path(rel).suffix.lower() in _READER_SUFFIXES


def _tracked(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [item.decode() for item in proc.stdout.split(b"\0") if item]


def shipped_files(root: Path = ROOT) -> tuple[list[Path], list[str]]:
    """(files to scan, errors): a tracked deploy file neither scanned nor listed in
    NOT_SHIPPED, an extension with no reader, or a NOT_SHIPPED entry matching no file."""
    names = set(_tracked(root))
    errors = [
        f"{name}: NOT_SHIPPED entry matches no tracked file"
        for name in sorted(NOT_SHIPPED)
        if name not in names
    ]
    # The docs check's own selection, never a second copy of its rules.
    user_docs = {path.relative_to(root).as_posix() for path in sd.doc_set(root)}
    files: list[Path] = []
    for name in sorted(names):
        if not _selected(name, user_docs):
            continue
        if not _has_reader(name):
            errors.append(f"{name}: no reader")
            continue
        files.append(root / name)
    return files, errors


def repo_errors(root: Path = ROOT) -> list[str]:
    doc = root / "docs/design/surface-4.0.md"
    text = doc.read_text(encoding="utf-8")
    table = CliTable.from_doc(text)
    rows = sd.Rows.from_doc(text)
    files, errors = shipped_files(root)
    hits: list[Hit] = []
    root_r = root.resolve()
    for path in files:
        rel = path.resolve().relative_to(root_r).as_posix()
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel}: no reader")
            continue
        hits.extend(scan_text(rel, body, table, rows))
    kept, stale = apply_allowed(hits, ALLOWED, table)
    kept.sort(key=lambda hit: (hit.file, hit.line, hit.item))
    errors.extend(f"{hit.file}:{hit.line}: {hit.cls} {hit.item}" for hit in kept)
    errors.extend(stale)
    return errors


def main() -> int:
    errors = repo_errors()
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
