#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Validated source factories for the timing-assert guard (MIK-8291).

A complete immutable `Revision` per side, validated `RawFn` spans built only
by the factories here, and the factory-owned `RawInventory` count facts. No
read callback, no facade import, no mutable global is captured: incomplete
evidence refuses carry.
"""

from __future__ import annotations

from array import array
from types import MappingProxyType
from typing import Mapping

from check_timing_asserts_core import FN, includers_of, tree_consts

_FACTORY = object()
_ABSENT = object()
_UNUSABLE = object()
_MODIFIERS = ("pub", "async", "unsafe", "const")
_UNSUPPORTED_PREFIX = ("extern", "default", "gen")
_HEX = frozenset("0123456789abcdefABCDEF")
_ESCAPES = frozenset("nrt\\'\"0")


def _is_ident_start(ch: str) -> bool:
    return ch == "_" or ch.isalpha()


def _is_ident_char(ch: str) -> bool:
    return ch == "_" or ch.isalnum()


def _mask_range(out: list[str], text: str, start: int, end: int) -> None:
    out.append("".join("\n" if c == "\n" else " " for c in text[start:end]))


def _escape_end(text: str, i: int) -> int | None:
    """Offset past the escape at backslash `i` in a char/byte-char, or None."""
    n = len(text)
    if i + 1 >= n:
        return None
    c = text[i + 1]
    if c in _ESCAPES:
        return i + 2
    if c == "x":
        if i + 3 < n and text[i + 2] in _HEX and text[i + 3] in _HEX:
            return i + 4
        return None
    if c == "u":
        if i + 2 >= n or text[i + 2] != "{":
            return None
        j = i + 3
        while j < n and text[j] in _HEX:
            j += 1
        if j == i + 3 or j > i + 9 or j >= n or text[j] != "}":
            return None
        return j + 1
    return None


def _string_end(text: str, quote: int) -> int | None:
    """Offset past the closing quote of the string opening at `quote`."""
    i, n = quote + 1, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        i += 1
    return None


def _raw_string_end(text: str, start: int) -> tuple[int, int] | None:
    """(quote offset, end) for a raw string whose prefix ends at `start`.

    `start` is just past the `r`/`br`/`cr` prefix; hashes then a quote open it.
    """
    i, n = start, len(text)
    hashes = 0
    while i < n and text[i] == "#":
        hashes += 1
        i += 1
    if i >= n or text[i] != '"':
        return None
    close = '"' + "#" * hashes
    j = text.find(close, i + 1)
    if j < 0:
        return None
    return i, j + len(close)


def _char_end(text: str, quote: int) -> int | None:
    """Offset past a char literal opening at `quote`, or None if not a char."""
    n = len(text)
    i = quote + 1
    if i >= n:
        return None
    if text[i] == "\\":
        end = _escape_end(text, i)
        if end is None or end >= n or text[end] != "'":
            return -1
        return end + 1
    if text[i] in ("'", "\n"):
        return None
    if i + 1 < n and text[i + 1] == "'":
        return i + 2
    return None


def mask_strings_and_comments(text: str) -> str | None:
    """Width-preserving mask: literal/comment chars become spaces, `\\n` kept.

    Maximal identifiers are tokenised first, so `r`/`b`/`br` are prefixes only
    as whole tokens and `r#ident` is not a raw string. Any unterminated or
    unsupported token yields None, which makes the file unusable for carry.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if _is_ident_start(c):
            j = i + 1
            while j < n and _is_ident_char(text[j]):
                j += 1
            word = text[i:j]
            if word == "r" and j < n and text[j] == "#" and j + 1 < n and _is_ident_start(text[j + 1]):
                k = j + 2
                while k < n and _is_ident_char(text[k]):
                    k += 1
                out.append(text[i:k])
                i = k
                continue
            if word in ("r", "br", "cr"):
                raw = _raw_string_end(text, j)
                if raw is not None:
                    _mask_range(out, text, i, raw[1])
                    i = raw[1]
                    continue
                if j < n and (text[j] == '"' or text[j] == "#"):
                    return None
            if word in ("b", "c") and j < n and text[j] == '"':
                end = _string_end(text, j)
                if end is None:
                    return None
                _mask_range(out, text, i, end)
                i = end
                continue
            if word == "b" and j < n and text[j] == "'":
                end = _char_end(text, j)
                if end is None or end < 0:
                    return None
                _mask_range(out, text, i, end)
                i = end
                continue
            out.append(word)
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            _mask_range(out, text, i, j)
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            if depth:
                return None
            _mask_range(out, text, i, j)
            i = j
            continue
        if c == '"':
            end = _string_end(text, i)
            if end is None:
                return None
            _mask_range(out, text, i, end)
            i = end
            continue
        if c == "'":
            end = _char_end(text, i)
            if end is not None and end < 0:
                return None
            if end is not None:
                _mask_range(out, text, i, end)
                i = end
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    masked = "".join(out)
    return masked if len(masked) == n else None


class ValidatedSource:
    """One strict-UTF-8 source with its mask and code-point-to-byte map.

    Sentinel-guarded and read-only; `validate_source` is the sole creator.
    `cp_to_byte[0] == 0`, `len(cp_to_byte) == len(text) + 1`, and the final
    entry is `len(raw)`.
    """

    __slots__ = ("_path", "_revision_id", "_raw", "_text", "_mask", "_cp_to_byte")

    def __init__(self, token, path, revision_id, raw, text, mask, cp_to_byte):
        if token is not _FACTORY:
            raise TypeError("ValidatedSource is created only by validate_source")
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_revision_id", revision_id)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_text", text)
        object.__setattr__(self, "_mask", mask)
        object.__setattr__(self, "_cp_to_byte", cp_to_byte)

    def __setattr__(self, name, value):
        raise AttributeError("ValidatedSource is read-only")

    @property
    def path(self):
        return self._path

    @property
    def revision_id(self):
        return self._revision_id

    @property
    def raw(self):
        return self._raw

    @property
    def text(self):
        return self._text

    @property
    def mask(self):
        return self._mask

    @property
    def cp_to_byte(self):
        return self._cp_to_byte


def validate_source(path, raw: bytes, revision_id) -> ValidatedSource | None:
    """The sole ValidatedSource creator: strict bytes in, no texts-only path."""
    if not isinstance(raw, (bytes, bytearray)):
        return None
    raw = bytes(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text.encode("utf-8") != raw:
        return None
    mask = mask_strings_and_comments(text)
    if mask is None or len(mask) != len(text):
        return None
    if text.isascii():
        cp_to_byte = range(len(text) + 1)
    else:
        offsets = array("Q")
        offsets.append(0)
        byte_at = 0
        for ch in text:
            byte_at += len(ch.encode("utf-8"))
            offsets.append(byte_at)
        cp_to_byte = memoryview(offsets.tobytes()).cast("Q")
    if cp_to_byte[0] != 0 or len(cp_to_byte) != len(text) + 1 or cp_to_byte[-1] != len(raw):
        return None
    return ValidatedSource(_FACTORY, path, revision_id, raw, text, mask, cp_to_byte)


class Revision:
    """A complete immutable revision. `make_revision` is the sole creator."""

    __slots__ = ("_revision_id", "_sources", "_present", "_consts", "_includers")

    def __init__(self, token, revision_id, sources, present, consts, includers):
        if token is not _FACTORY:
            raise TypeError("Revision is created only by make_revision")
        object.__setattr__(self, "_revision_id", revision_id)
        object.__setattr__(self, "_sources", sources)
        object.__setattr__(self, "_present", present)
        object.__setattr__(self, "_consts", consts)
        object.__setattr__(self, "_includers", includers)

    def __setattr__(self, name, value):
        raise AttributeError("Revision is read-only")

    @property
    def revision_id(self):
        return self._revision_id

    @property
    def sources(self):
        return self._sources

    @property
    def present(self):
        return self._present

    @property
    def consts(self):
        return self._consts

    @property
    def includers(self):
        return self._includers


def make_revision(revision_id, raw_by_path: Mapping[str, bytes], present: frozenset[str]) -> Revision | None:
    """The sole Revision creator: bytes in, complete or None.

    Rejects unless `set(raw_by_path) == present` and every source validates;
    texts, consts, and includers are derived only from those sources.
    """
    try:
        present = frozenset(present)
        if set(raw_by_path) != set(present):
            return None
        sources = {}
        for path in sorted(present):
            source = validate_source(path, raw_by_path[path], revision_id)
            if source is None:
                return None
            sources[path] = source
        texts = {path: source.text for path, source in sources.items()}
        consts = MappingProxyType({name: tuple(entries) for name, entries in tree_consts(texts).items()})
        includers = MappingProxyType(dict(includers_of(texts)))
    except Exception:
        return None
    return Revision(_FACTORY, revision_id, MappingProxyType(sources), present, consts, includers)


class RawFn:
    """A validated raw fn span. `build_raw_fns` is the sole creator; no
    exported constructor accepts caller offsets or raw slices."""

    __slots__ = ("_name", "_raw", "_source", "_start_cp", "_end_cp", "_body_cp")

    def __init__(self, token, name, raw, source, start_cp, end_cp, body_cp):
        if token is not _FACTORY:
            raise TypeError("RawFn is created only by build_raw_fns")
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_source", source)
        object.__setattr__(self, "_start_cp", start_cp)
        object.__setattr__(self, "_end_cp", end_cp)
        object.__setattr__(self, "_body_cp", body_cp)

    def __setattr__(self, name, value):
        raise AttributeError("RawFn is read-only")

    @property
    def name(self):
        return self._name

    @property
    def raw(self):
        return self._raw

    @property
    def source(self):
        return self._source

    @property
    def start_cp(self):
        return self._start_cp

    @property
    def end_cp(self):
        return self._end_cp

    @property
    def body_cp(self):
        return self._body_cp


def _modifier_start(mask: str, fn_at: int) -> int | None:
    """Canonical token start: back over contiguous supported modifiers only.

    Leading whitespace, blank lines, indentation, and `#[...]` attributes are
    excluded; `extern`/`default`/unknown word prefixes reject the file.
    """
    start = fn_at
    while True:
        end = start
        while end > 0 and mask[end - 1].isspace():
            end -= 1
        if end == 0:
            return start
        if mask[end - 1] == "]":
            return start
        if mask[end - 1] == ")":
            depth, open_at = 0, end - 1
            while open_at >= 0:
                depth += {")": 1, "(": -1}.get(mask[open_at], 0)
                if depth == 0:
                    break
                open_at -= 1
            if open_at < 0 or depth != 0:
                return None
            word_end = open_at
            word_start = word_end
            while word_start > 0 and _is_ident_char(mask[word_start - 1]):
                word_start -= 1
            if mask[word_start:word_end] != "pub":
                return None
            start = word_start
            continue
        if not _is_ident_char(mask[end - 1]):
            return start
        word_start = end
        while word_start > 0 and _is_ident_char(mask[word_start - 1]):
            word_start -= 1
        word = mask[word_start:end]
        if word in _MODIFIERS:
            start = word_start
            continue
        if word in _UNSUPPORTED_PREFIX:
            return None
        # An adjacent unknown word can only be a prefix this factory does not
        # support (items are otherwise separated by `{`, `}`, `;`, or `]`).
        return None


def _signature_body(mask: str, pos: int) -> int | None:
    """Body `{` offset for the signature starting at `pos`, or -1 for a
    declaration, or None when the signature is unsupported or unbalanced."""
    stack: list[str] = []
    seen_params = False
    params_done = False
    i, n = pos, len(mask)
    while i < n:
        c = mask[i]
        in_brace = "{" in stack
        if c in "([":
            if c == "(" and not stack and not seen_params:
                seen_params = True
            stack.append(c)
        elif c == ")":
            if not stack or stack[-1] != "(":
                return None
            stack.pop()
            if seen_params and not stack:
                params_done = True
        elif c == "]":
            if not stack or stack[-1] != "[":
                return None
            stack.pop()
        elif c == "<":
            if not in_brace:
                if i + 1 < n and mask[i + 1] in "<=":
                    return None
                stack.append(c)
        elif c == ">":
            if not in_brace:
                if i > 0 and mask[i - 1] == "-":
                    pass  # the `->` return arrow, never a generic close
                elif stack and stack[-1] == "<":
                    stack.pop()
                else:
                    return None
        elif c == "{":
            if not stack:
                if not params_done:
                    return None
                return i
            stack.append(c)
        elif c == "}":
            if not stack or stack[-1] != "{":
                return None
            stack.pop()
        elif c == ";" and not stack:
            return -1 if params_done else None
        i += 1
    return None


def _body_end(mask: str, body_cp: int) -> int | None:
    depth, i = 0, body_cp
    while i < len(mask):
        depth += {"{": 1, "}": -1}.get(mask[i], 0)
        i += 1
        if depth == 0:
            return i
    return None


def build_raw_fns(src: ValidatedSource) -> tuple[RawFn, ...] | None:
    """The sole RawFn creator, from a validated source's stored bytes only.

    All boundary validation passes before any RawFn exists; byte extraction
    uses only `src.cp_to_byte` and is verified against the text slice.
    """
    if not isinstance(src, ValidatedSource):
        return None
    mask, text = src.mask, src.text
    pending = []
    for m in FN.finditer(mask):
        fn_at, name, name_cp = m.start(), m.group(1), m.start(1)
        start_cp = _modifier_start(mask, fn_at)
        if start_cp is None:
            return None
        token_end = start_cp
        while token_end < len(mask) and _is_ident_char(mask[token_end]):
            token_end += 1
        if mask[start_cp:token_end] not in (*_MODIFIERS, "fn"):
            return None
        if start_cp > 0 and _is_ident_char(mask[start_cp - 1]):
            return None
        body_cp = _signature_body(mask, m.end())
        if body_cp is None:
            return None
        if body_cp < 0:
            continue
        end_cp = _body_end(mask, body_cp)
        if end_cp is None:
            return None
        if not (start_cp < name_cp < body_cp < end_cp <= len(text)):
            return None
        pending.append((name, start_cp, end_cp, body_cp))
    pending.sort(key=lambda span: (span[1], span[2]))
    for a in range(len(pending)):
        for b in range(a + 1, len(pending)):
            _, a_start, a_end, _ = pending[a]
            _, b_start, b_end, _ = pending[b]
            if a_end <= b_start or b_end <= a_start:
                continue
            nested = (a_start <= b_start and b_end <= a_end) or (b_start <= a_start and a_end <= b_end)
            if not nested:
                return None
    built = []
    for name, start_cp, end_cp, body_cp in pending:
        raw = src.raw[src.cp_to_byte[start_cp] : src.cp_to_byte[end_cp]]
        if raw != text[start_cp:end_cp].encode("utf-8"):
            return None
        built.append(RawFn(_FACTORY, name, raw, src, start_cp, end_cp, body_cp))
    return tuple(built)


class RawInventory:
    """All validated spans of one source, nested included, in span order.

    Sentinel-guarded and read-only; `build_raw_inventory` is the sole
    creator. Count facts derive only from this immutable tuple, so no
    caller supplies a span list or a count.
    """

    __slots__ = ("_source", "_spans")

    def __init__(self, token, source, spans):
        if token is not _FACTORY:
            raise TypeError("RawInventory is created only by build_raw_inventory")
        object.__setattr__(self, "_source", source)
        object.__setattr__(self, "_spans", spans)

    def __setattr__(self, name, value):
        raise AttributeError("RawInventory is read-only")

    def __delattr__(self, name):
        raise AttributeError("RawInventory is read-only")

    @property
    def source(self):
        return self._source

    @property
    def spans(self):
        return self._spans

    def named(self, fn) -> tuple[RawFn, ...]:
        return tuple(span for span in self._spans if span.name == fn)

    def count_raw(self, fn, raw: bytes) -> int:
        return sum(1 for span in self._spans if span.name == fn and span.raw == raw)


def build_raw_inventory(src: ValidatedSource) -> RawInventory | None:
    """The sole RawInventory creator, from `build_raw_fns` spans only."""
    spans = build_raw_fns(src)
    if spans is None or any(span.source is not src for span in spans):
        return None
    return RawInventory(_FACTORY, src, spans)
