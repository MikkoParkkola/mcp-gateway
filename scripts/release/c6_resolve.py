#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Resolve every C6 gate-day obligation to its function, wherever it now lives (MIK-8245).

    c6_resolve.py [--tree REV] [--manifest DIR]

The frozen ranking (docs/release/v4.0.0-c6-mutation-ranking.tsv) names each obligation by the
file it was in when drawn. A function moved since then would leave its fail-open patch unable to
apply, and the mutants runner scores that VOID, which G9 lets an understudy replace: the
obligation would leave the sample with nothing said. This resolver runs first, on every
release-line push and pull request (.github/workflows/c6-obligations.yml), and on gate day.

For each active obligation (the 68 SAMPLE rows, as replaced by
docs/release/c6-gap/v4.0.0-c6-replacements.tsv) it:
  1. finds the function by identity (Type::name or name), not by recorded file;
  2. re-targets the obligation's patch to that file;
  3. requires every hunk's old-side lines to occur exactly once in the file, inside that
     function's body (a patch that applies is not proof of WHICH function it mutates);
  4. requires `git apply --check` of the re-targeted patch against REV;
  5. requires the killer-gap row's test filter to name one test: its last `::` segment is a
     fn defined exactly once in the crate the arguments select (`--lib` or `--test X`), and
     a full path is that fn's path in the crate's module tree. Cargo matches a filter as a
     substring of the test path, so a test moved to another module would match nothing and
     the row would come back VOID instead of judging its killer;
  6. requires the row's declared_assertion (`<file>:<line> <text> [stmt:<8 hex>]`) to name a
     line inside the killer (or inside a helper F the killer calls, for a `[via F]` row) that
     still carries the recorded text and starts the statement with that digest, exactly once,
     all in the file as the mutant run compiles it (the row's patch applied when it edits that
     file). G7 scores a RED only when the panic is at that file:line.
Prints one line per obligation and `N framed items unresolved`; exits 1 when N > 0.
--manifest DIR writes the re-targeted patches and a mutants manifest for the runner.
Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import enum
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RANKING = "docs/release/v4.0.0-c6-mutation-ranking.tsv"
REPLACEMENTS = "docs/release/c6-gap/v4.0.0-c6-replacements.tsv"
PATCHES = "docs/release/c6-gap/patches"
# The patch directory of each named path.
PATCH_DIR = {
    "HTTP dispatch": "http", "startup": "startup", "OAuth": "oauth", "stdio dispatch": "stdio",
    "tasks": "tasks", "account paths": "acct", "bridge": "bridge",
}


# --------------------------------------------------------------------------------------------
# Lexing: Rust source with comments and literals blanked, so braces and `fn` are code only.
# --------------------------------------------------------------------------------------------

class Unsupported(Exception):
    """Source this scanner cannot read with certainty; the caller reports it unresolved."""


class Wipe(enum.Enum):
    """What `blank` replaces with spaces."""

    COMMENTS_AND_LITERALS = "comments and literals"
    # Literals kept: for a scan whose patterns include string literals.
    COMMENTS = "comments"


def blank(source: str, mode: Wipe = Wipe.COMMENTS_AND_LITERALS) -> str:
    """`source` with every comment and string, raw string, byte string and char literal
    replaced by spaces (only comments with Wipe.COMMENTS), newlines kept, so offsets and
    line numbers are unchanged."""
    out = list(source)
    i, n = 0, len(source)

    def wipe(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    def wipe_literal(a: int, b: int) -> None:
        if mode is Wipe.COMMENTS_AND_LITERALS:
            wipe(a, b)

    while i < n:
        c = source[i]
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
        elif source.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif source.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                raise Unsupported("unterminated block comment")
            wipe(i, j)
            i = j
        elif m := re.compile(r'[bc]?r(#*)"').match(source, i) if c in "bcr" and _ident_start(source, i) else None:
            close = '"' + m.group(1)
            j = source.find(close, m.end())
            if j < 0:
                raise Unsupported("unterminated raw string")
            wipe_literal(i, j + len(close))
            i = j + len(close)
        elif c == '"':  # a b"..." or c"..." prefix is just an identifier character before it
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            if j >= n:
                raise Unsupported("unterminated string")
            wipe_literal(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'").match(source, i)
            if m:
                wipe_literal(i, m.end())
                i = m.end()
            else:
                i += 1  # a lifetime or label: 'a
        else:
            # Plain code: jump to the next place a branch above can start (a scan of every
            # character in Python made a whole-crate module walk take seconds per thousand files).
            m = _LEXEME.search(source, i + 1)
            i = m.start() if m else n
    return "".join(out)


# Every position where a branch of `blank` can fire: a comment, a quote, or a raw string's
# prefix at the start of an identifier (what `_ident_start` checks).
_LEXEME = re.compile(r"""//|/\*|"|'|(?<!\w)[bc]?r#*\"""")


def _ident_start(source: str, i: int) -> bool:
    """True when position i does not continue an identifier (so `r"` is a raw string, not `bar"`)."""
    return i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_")


@dataclass(frozen=True)
class Decl:
    """One `fn` declaration: its name, the type or trait of the enclosing impl/trait block
    (None at module level), and its 1-based line span from `fn` to the body's closing brace."""

    name: str
    owner: str | None
    start: int
    end: int
    # Character offsets of `fn` and of the closing brace: nesting is decided on these, since two
    # functions can share a line without either containing the other.
    at: int = 0
    stop: int = 0


_IMPL_HEAD = re.compile(r"\b(impl|trait)\b")
_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)")


def _owner_of(header: str, kind: str) -> str | None:
    """The type an `impl ... {` header implements for, or the trait a `trait X {` names."""
    text = _strip_generics(header)
    if kind == "trait":
        m = re.match(r"\s*trait\s+([A-Za-z_]\w*)", text)
        return m.group(1) if m else None
    text = re.sub(r"\bwhere\b.*", "", text, flags=re.S)
    target = text.split(" for ", 1)[1] if " for " in text else text[text.index("impl") + 4:]
    names = re.findall(r"[A-Za-z_]\w*", target)
    return names[-1] if names else None


def _strip_generics(text: str) -> str:
    """`text` without its `<...>` groups. The `>` of an `->` closes nothing: read as a closer,
    `impl Guard<fn() -> Other>` would leave `Other` as the owner."""
    out, depth = [], 0
    for k, ch in enumerate(text):
        if ch == "<":
            depth += 1
        elif ch == ">" and k and text[k - 1] == "-":
            if not depth:
                out.append(ch)
        elif ch == ">" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def declarations(source: str) -> list[Decl]:
    """Every `fn` in `source` with its owner and body span, read from the blanked text."""
    code = blank(source)
    line_at = [0] * (len(code) + 1)
    line = 1
    for k, ch in enumerate(code):
        line_at[k] = line
        if ch == "\n":
            line += 1
    line_at[len(code)] = line

    decls: list[Decl] = []
    # One entry per open brace: (kind, owner). Only a fn opened directly in an `impl` or `trait`
    # block belongs to it; a fn nested in a function body, or in a plain block, belongs to no type.
    scopes: list[tuple[str, str | None]] = []
    pending: tuple[str, int] | None = None  # (kind, offset) of an impl/trait header awaiting `{`
    fn_open: list[tuple[str, int, int, str | None, int]] = []  # (name, line, body depth, owner, offset)
    fn_body_next = False  # the next `{` opens the body of the fn just declared
    header_depth = 0  # bracket depth inside a pending impl/trait header
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if pending is not None and ch in "([<" :
            header_depth += 1
        elif pending is not None and ch in ")]" or (ch == ">" and pending is not None and code[i - 1] != "-"):
            header_depth = max(header_depth - 1, 0)
        if ch == "{":
            if pending is not None and header_depth:
                scopes.append(("block", None))  # e.g. a const-generic `{ 1 }` inside the header
                i += 1
                continue
            if pending is not None:
                kind, at = pending
                scopes.append(("impl", _owner_of(code[at:i], kind) or "?"))
                pending = None
            elif fn_body_next:
                scopes.append(("fn", None))
                fn_body_next = False
            else:
                scopes.append(("block", None))
            i += 1
            continue
        if ch == "}":
            if not scopes:
                raise Unsupported(f"unbalanced closing brace at line {line_at[i]}")
            if fn_open and fn_open[-1][2] == len(scopes):
                name, start, _, owner, at = fn_open.pop()
                decls.append(Decl(name, owner, start, line_at[i], at, i))
            scopes.pop()
            i += 1
            continue
        if ch == ";" and pending is not None and not header_depth:
            pending = None  # a stray `impl`/`trait` word; a `;` inside the header's brackets is not it
        word = i == 0 or not (code[i - 1].isalnum() or code[i - 1] == "_")
        if word and (m := _MACRO_RULES.match(code, i)):
            # A macro template is token trees, not items: a `fn` in it is never a declaration.
            i = _matching(code, m.end() - 1, line_at)
            continue
        if word and (m := _IMPL_HEAD.match(code, i)):
            pending, header_depth = (m.group(1), i), 0
            i = m.end()
            continue
        if word and (m := _FN.match(code, i)):
            j = m.end()
            # The body opens at the first `{` at signature depth; a `;` first means no body.
            depth = 0
            while j < n:
                c = code[j]
                if c in "(<[":
                    depth += 1
                elif c in ")>]" and depth:
                    depth -= 1
                elif c == ";" and depth == 0:
                    break
                elif c == "{" and depth == 0:
                    parent = scopes[-1] if scopes else ("block", None)
                    owner = parent[1] if parent[0] == "impl" else None
                    fn_open.append((m.group(1), line_at[i], len(scopes) + 1, owner, i))
                    fn_body_next = True
                    break
                j += 1
            i = j if fn_body_next else m.end()
            continue
        i += 1
    if scopes or fn_open:
        raise Unsupported("unbalanced braces at end of file")
    decls.sort(key=lambda d: d.start)
    return decls


# A macro definition or invocation: its token tree is not items, whatever it spells. A `fn` only a
# macro emits is then not found, so its obligation fails loudly rather than resolving to text.
_MACRO_RULES = re.compile(r"(?:macro_rules\s*!\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*!)\s*[({\[]")


def _matching(code: str, open_at: int, line_at: list[int]) -> int:
    """The offset just past the bracket closing the one at `open_at` (all three kinds nest)."""
    depth, j = 0, open_at
    while j < len(code):
        if code[j] in "({[":
            depth += 1
        elif code[j] in ")}]":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Unsupported(f"unterminated macro at line {line_at[open_at]}")


# --------------------------------------------------------------------------------------------
# The obligations, the tree, and the patches.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Obligation:
    """One active gate-day obligation: its slot (path, rank) and the function it binds."""

    path: str          # named path, e.g. "HTTP dispatch"
    rank: int          # the slot's rank in the ranking
    file: str          # file recorded for the bound function
    qualified: str     # Type::fn or fn
    occurrence: int    # nth `fn <name>` in the recorded file
    patch: str         # repository path of its fail-open patch
    note: str          # why this binding (SAMPLE, or the replacement rule)


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader((l for l in text.splitlines() if not l.startswith("#")), delimiter="\t"))


class Tree:
    """Read-only view of one revision through git, so no checkout is needed (gate day passes FROZEN)."""

    def __init__(self, rev: str, root: Path = ROOT) -> None:
        self.root = root
        self.rev = self._git("rev-parse", "--verify", f"{rev}^{{commit}}").strip()
        self._cache: dict[str, str] = {}
        self._index: dict | None = None
        self._files: set[str] | None = None
        self._scratch: tempfile.TemporaryDirectory | None = None

    def _git(self, *args: str, env: dict | None = None) -> str:
        done = subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, env=env)
        if done.returncode:
            raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()}")
        return done.stdout

    def read(self, path: str) -> str:
        if path not in self._cache:
            self._cache[path] = self._git("show", f"{self.rev}:{path}")
        return self._cache[path]

    def ls(self, prefix: str) -> list[str]:
        return self._git("ls-tree", "-r", "--name-only", self.rev, prefix).split()

    def applies(self, patch: str) -> tuple[bool, str]:
        """Whether `patch` applies to this revision, checked against one scratch index of it
        (`--check` never writes the index, so every patch is checked against the same tree)."""
        if self._index is None:
            self._scratch = tempfile.TemporaryDirectory()
            self._index = {**os.environ, "GIT_INDEX_FILE": str(Path(self._scratch.name, "index"))}
            self._git("read-tree", self.rev, env=self._index)
        done = subprocess.run(["git", "apply", "--cached", "--check", "-"], cwd=self.root,
                              input=patch, capture_output=True, text=True, env=self._index)
        return done.returncode == 0, done.stderr.strip()

    def prefetch(self, prefix: str) -> None:
        """Reads every `.rs` file under `prefix` into the cache with one `git cat-file --batch`
        (a module walk reads thousands; one `git show` each takes minutes)."""
        paths = [p for p in self.ls(prefix) if p.endswith(".rs") and p not in self._cache]
        done = subprocess.run(["git", "cat-file", "--batch"], cwd=self.root, capture_output=True,
                              input="".join(f"{self.rev}:{p}\n" for p in paths).encode())
        if done.returncode:
            raise RuntimeError(f"git cat-file --batch: {done.stderr.decode().strip()}")
        out, at = done.stdout, 0
        for p in paths:
            end = out.index(b"\n", at)
            size = int(out[at:end].split()[2])  # "<sha> blob <size>"
            self._cache[p] = out[end + 1:end + 1 + size].decode()
            at = end + 1 + size + 1

    def exists(self, path: str) -> bool:
        if self._files is None:
            self._files = set(self._git("ls-tree", "-r", "--name-only", self.rev).split())
        return path in self._files

    def files_declaring(self, name: str) -> list[str]:
        """The `src/**.rs` files whose text has `fn <name>`, found by one `git grep`."""
        done = subprocess.run(["git", "grep", "-l", "-E", rf"(^|[^[:alnum:]_])fn[[:space:]]+{re.escape(name)}([^[:alnum:]_]|$)",
                               self.rev, "--", "src/*.rs", "src/**/*.rs"],
                              cwd=self.root, capture_output=True, text=True)
        if done.returncode not in (0, 1):
            raise RuntimeError(f"git grep: {done.stderr.strip()}")
        return sorted({line.split(":", 1)[1] for line in done.stdout.splitlines() if ":" in line})


def _patch_for(tree: Tree, path: str, rank: int) -> str:
    folder = f"{PATCHES}/{PATCH_DIR[path]}"
    hits = [p for p in tree.ls(folder) if Path(p).name.startswith(f"{rank}_") and p.endswith(".patch")]
    if len(hits) != 1:
        raise LookupError(f"{path} rank {rank}: {len(hits)} patches in {folder}")
    return hits[0]


def obligations(tree: Tree) -> list[Obligation]:
    """The SAMPLE rows of the frozen ranking, with each recorded replacement applied to its slot.

    A replacement keeps the slot (named path + rank, so the quota is unchanged) and binds it to
    another function: an understudy of the ranking (G9, G11) or a two-seat successor (G4)."""
    ranking = _rows(tree.read(RANKING))
    by_slot = {(r["named_path"], int(r["rank"])): r for r in ranking}
    active = {key: r for key, r in by_slot.items() if r["status"] == "SAMPLE"}
    notes = {key: "SAMPLE" for key in active}
    patches: dict[tuple[str, int], str | None] = {key: None for key in active}
    replaced: set[tuple[str, int]] = set()
    for rep in _rows(tree.read(REPLACEMENTS)):
        slot = (rep["named_path"], int(rep["slot_rank"]))
        if slot not in active:
            raise LookupError(f"replacement for {slot}: not a SAMPLE slot")
        if slot in replaced:
            raise LookupError(f"replacement for {slot}: the slot is replaced twice")
        replaced.add(slot)
        if rep["rule"] in ("G9", "G11"):
            under = by_slot.get((rep["named_path"], int(rep["understudy_rank"])))
            if under is None or under["status"] != "understudy":
                raise LookupError(f"replacement for {slot}: understudy rank {rep['understudy_rank']} not found")
            active[slot] = under
            patches[slot] = _patch_for(tree, rep["named_path"], int(rep["understudy_rank"]))
        elif rep["rule"] == "qualify":
            # The frozen row names a method by its bare name; this adds the owner, nothing else.
            bare, given = active[slot]["qualified"], rep["qualified"].split("::")
            if "::" in bare or len(given) != 2 or given[1] != bare or not given[0]:
                raise LookupError(f"replacement for {slot}: qualify may only turn a bare name into Owner::name")
            active[slot] = {**active[slot], "qualified": rep["qualified"]}
        elif rep["rule"] == "G4-successor":
            active[slot] = {**active[slot], "file": rep["file"], "qualified": rep["qualified"],
                            "occurrence": rep["occurrence"]}
        else:
            raise LookupError(f"replacement for {slot}: unknown rule {rep['rule']!r}")
        notes[slot] = f"{rep['rule']}: {rep['evidence']}"
    # One function per slot and one slot per function: a reused understudy or successor would
    # count one mutant twice as two obligations. G11 falls through at most once per path.
    bound: dict[tuple[str, str, int], tuple[str, int]] = {}
    for slot, r in active.items():
        key = (r["file"], r["qualified"], int(r["occurrence"]))
        if key in bound:
            raise LookupError(f"{slot} and {bound[key]} bind the same function {r['qualified']}")
        bound[key] = slot
    g11 = [rep["named_path"] for rep in _rows(tree.read(REPLACEMENTS)) if rep["rule"] == "G11"]
    if dup := sorted({p for p in g11 if g11.count(p) > 1}):
        raise LookupError(f"G11 used more than once on: {', '.join(dup)}")
    if len(set(patches[s] or "" for s in active) - {""}) != sum(1 for s in active if patches[s]):
        raise LookupError("two slots share one understudy patch")
    return [
        Obligation(path, rank, r["file"], r["qualified"], int(r["occurrence"]),
                   patches[(path, rank)] or _patch_for(tree, path, rank), notes[(path, rank)])
        for (path, rank), r in sorted(active.items())
    ]


# --------------------------------------------------------------------------------------------
# Resolution of one obligation.
# --------------------------------------------------------------------------------------------

@dataclass
class Outcome:
    obligation: Obligation
    status: str                 # in-place | moved | unresolved
    file: str | None = None     # resolved file
    detail: str = ""
    patch: str | None = None    # the re-targeted patch text, when resolved
    at: int = -1                # offset of the resolved `fn`, to catch two slots on one function


def _bind_recorded(tree: Tree, ob: Obligation, name: str, owner: str | None,
                   files: set[str]) -> Decl | None:
    """The declaration the frozen row names: the occurrence-th `fn <name>` line of the recorded
    file (the inventory counts raw lines), kept only when it still has the recorded owner: a bare
    name is a free function. The frozen rows that name a method bare are given their owner by a
    `qualify` replacement, so an owner never acts as a wildcard."""
    if ob.file not in files:
        return None
    source = tree.read(ob.file)
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    lines = [k + 1 for k, text in enumerate(source.splitlines()) if pattern.search(text)]
    if len(lines) < ob.occurrence:
        return None
    at = lines[ob.occurrence - 1]
    for decl in declarations(source):
        if decl.start == at and decl.name == name and decl.owner == owner:
            return decl
    return None


def _hunks(patch: str) -> list[list[tuple[str, str]]]:
    """Each hunk as (marker, text) lines: ' ' context, '-' removed, '+' added."""
    hunks: list[list[tuple[str, str]]] = []
    in_hunks = False  # file headers (`---`/`+++`) come only before a file's first hunk
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            in_hunks = False
        elif line.startswith("@@"):
            hunks.append([])
            in_hunks = True
        elif in_hunks and line[:1] in (" ", "-", "+"):
            hunks[-1].append((line[0], line[1:]))
    return hunks


def _splice(lines: list[str], edits: list[tuple[int, int, list[str]]]) -> str | None:
    """`lines` (kept ends) with each edit (first old line index, old line count, new lines)
    put in, as one text; None when two edits overlap."""
    out, cursor = [], 0
    for first, count, new in sorted(edits):
        if first < cursor:
            return None
        out.extend(lines[cursor:first])
        out.extend(new)
        cursor = first + count
    return "".join(out + lines[cursor:])


def _contained(source: str, decl: Decl, patch: str) -> str | None:
    """None when every hunk anchors to exactly one place in the file and the patched file differs
    from `source` only inside `decl`: the text before its `fn` and after its closing brace stay
    byte for byte. A patch that merely applies could be mutating a neighbouring function, an item
    sharing a line with it, or code added after it; none of those leave that text unchanged."""
    lines = source.splitlines(keepends=True)
    plain = [line.rstrip("\n") for line in lines]
    edits = []  # (first old line index, old line count, new lines)
    for k, hunk in enumerate(_hunks(patch), 1):
        old = [text for mark, text in hunk if mark != "+"]
        if not old:
            return f"hunk {k} has no context to anchor it"
        hits = [i for i in range(len(plain) - len(old) + 1) if plain[i:i + len(old)] == old]
        if len(hits) != 1:
            return f"hunk {k} matches {len(hits)} places in the file"
        if all(mark == " " for mark, _ in hunk):
            return f"hunk {k} changes nothing"
        edits.append((hits[0], len(old), [text + "\n" for mark, text in hunk if mark != "-"]))
    patched_text = _splice(lines, edits)
    if patched_text is None:
        return "two hunks overlap"
    before, after = source[:decl.at], source[decl.stop + 1:]
    if not patched_text.startswith(before):
        return f"it changes text before {decl.name} (line {decl.start})"
    if not patched_text.endswith(after) or len(patched_text) < len(before) + len(after):
        return f"it changes text after {decl.name} (line {decl.end})"
    # What lies between must still be exactly one function, from its `fn` to its own closing
    # brace: text added after that brace on its line would otherwise pass as "inside".
    middle = patched_text[len(before):len(patched_text) - len(after)]
    try:
        whole = [d for d in declarations(middle) if d.at == 0]
    except Unsupported as why:
        return f"the patched {decl.name} cannot be read: {why}"
    if len(whole) != 1 or whole[0].stop != len(middle) - 1:
        return f"it changes text after {decl.name} (line {decl.end})"
    return None


_NOT_A_TEXT_EDIT = re.compile(r"^(rename from|rename to|copy from|copy to|old mode|new mode|"
                              r"deleted file mode|new file mode|similarity index|GIT binary patch|Binary files)",
                              re.M)


def _patch_shape(patch: str) -> tuple[str | None, str | None]:
    """(the one file the patch edits, None) when it is a plain text edit of one existing file;
    otherwise (None, why). A rename, a mode change, a binary or a hunkless patch mutates no
    function, whatever file it names."""
    if m := _NOT_A_TEXT_EDIT.search(patch):
        return None, f"patch is not a plain text edit ({m.group(1)})"
    heads = re.findall(r"^diff --git a/(\S+) b/(\S+)$", patch, flags=re.M)
    if len(heads) != 1:
        return None, f"patch touches {len(heads)} files, expected 1"
    a, b = heads[0]
    minus = re.findall(r"^--- a/(\S+)$", patch, flags=re.M)
    plus = re.findall(r"^\+\+\+ b/(\S+)$", patch, flags=re.M)
    if a != b or minus != [a] or plus != [a]:
        return None, "patch source and destination paths differ"
    if not re.search(r"^@@ ", patch, flags=re.M):
        return None, "patch has no text hunk"
    return a, None


def _reanchor(patch: str, source: str) -> str:
    """`patch` with each hunk header rewritten to the line its old side occupies in `source`
    (found exactly once by `_contained`), so it applies where it was located, not by offset."""
    lines = source.splitlines()
    out, delta = [], 0
    hunk_iter = iter(_hunks(patch))
    for line in patch.splitlines(keepends=True):
        m = re.match(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@(.*)", line)
        if m:
            hunk = next(hunk_iter)
            old = [text for mark, text in hunk if mark != "+"]
            new_len = sum(1 for mark, _ in hunk if mark != "-")
            at = next(s + 1 for s in range(len(lines) - len(old) + 1) if lines[s:s + len(old)] == old)
            line = f"@@ -{at},{len(old)} +{at + delta},{new_len} @@{m.group(3)}\n"
            delta += new_len - len(old)
        out.append(line)
    return "".join(out)


def _retarget(patch: str, old: str, new: str) -> str:
    if old == new:
        return patch
    out = []
    for line in patch.splitlines(keepends=True):
        if line.startswith("diff --git "):
            line = f"diff --git a/{new} b/{new}\n"
        elif line.startswith("--- a/"):
            line = f"--- a/{new}\n"
        elif line.startswith("+++ b/"):
            line = f"+++ b/{new}\n"
        out.append(line)
    return "".join(out)


def resolve(tree: Tree, ob: Obligation, rust_files: set[str]) -> Outcome:
    name = ob.qualified.split("::")[-1]
    owner = ob.qualified.split("::")[-2] if "::" in ob.qualified else None
    patch = tree.read(ob.patch)
    target, bad = _patch_shape(patch)
    if bad:
        return Outcome(ob, "unresolved", detail=bad)
    try:
        decl = _bind_recorded(tree, ob, name, owner, rust_files)
        where = ob.file
        if decl is None:
            found = []
            for path in tree.files_declaring(name):
                # Exact owner: a bare name is a free function here, so an obligation never
                # drifts onto a same-named method; a moved method named bare fails loudly.
                found += [(path, d) for d in declarations(tree.read(path))
                          if d.name == name and d.owner == owner]
            if not found:
                return Outcome(ob, "unresolved", detail=f"{ob.qualified} not found in src/")
            if len(found) > 1:
                return Outcome(ob, "unresolved",
                               detail=f"{ob.qualified} is ambiguous: {', '.join(f'{p}:{d.start}' for p, d in found)}")
            where, decl = found[0]
        moved = where != ob.file
        text = _retarget(patch, target, where)
        why = _contained(tree.read(where), decl, text)
    except Unsupported as unreadable:
        return Outcome(ob, "unresolved", detail=f"cannot read the source with certainty: {unreadable}")
    if why:
        return Outcome(ob, "unresolved", where, f"patch does not mutate {ob.qualified}: {why}")
    text = _reanchor(text, tree.read(where))
    ok, error = tree.applies(text)
    if not ok:
        return Outcome(ob, "unresolved", where, f"patch does not apply at {where}: {error.splitlines()[0] if error else 'rejected'}")
    return Outcome(ob, "moved" if moved else "in-place", where,
                   f"{ob.file} -> {where}" if moved else "", text, decl.at)


# --------------------------------------------------------------------------------------------
# Killer filters: the module tree of a crate, and the one test a filter names in it.
# --------------------------------------------------------------------------------------------

GAP_TABLE = "docs/release/c6-gap/v4.0.0-c6-gap-table.tsv"
_MOD = re.compile(r"\bmod\s+([A-Za-z_]\w*)\s*([;{])")
_MOD_WORD = re.compile(r"\bmod\b")
_PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
_PATH_WORD = re.compile(r"#\[\s*path\b")
# `fn <name>` in raw text with only whitespace or line comments between: for a file with no
# block comment, a superset of what declarations() finds in the blanked text.
_FN_LINE = re.compile(r"\bfn(?:\s|//[^\n]*)+([A-Za-z_]\w*)")
# A test attribute directly on a fn: #[test], #[tokio::test], #[tokio :: test(...)]; not #[cfg(test)].
_TEST_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*\s*::\s*)*test\b")


@dataclass(frozen=True)
class ModFile:
    """One file of a crate's module tree: its module path, and its inline `mod x { }` blocks
    as (open offset, close offset, name), so a fn's path adds the blocks around it."""

    path: str
    inline: tuple[tuple[int, int, str], ...]


# Per crate root: its module tree and fn-name index, or the reason it cannot be read.
Crates = dict[str, "tuple[dict[str, ModFile], dict[str, list[str]]] | Unsupported"]

def module_tree(tree: Tree, root: str) -> dict[str, ModFile]:
    """Every file of the crate rooted at `root`, found the way rustc finds it: `mod x;` loads
    x.rs or x/mod.rs beside a mod-rs file (the root, a mod.rs, a #[path] file), under a
    directory named for any other file, inside the directories of enclosing inline modules,
    or the #[path] file named. A declared module whose file is missing is unreadable."""
    tree.prefetch(os.path.dirname(root))
    files: dict[str, ModFile] = {}
    todo = [(root, "", True)]  # (file, module path, children resolve from the file's own directory)
    while todo:
        path, module, owns_dir = todo.pop()
        if path in files:
            raise Unsupported(f"{path} is mounted twice")
        source = tree.read(path)
        if not _MOD_WORD.search(source):
            files[path] = ModFile(module, ())  # no `mod` anywhere: no child, no inline block
            continue
        code = blank(source)
        # Literals are kept only to read a #[path]; a file that names none needs no second pass.
        kept = blank(source, Wipe.COMMENTS) if _PATH_WORD.search(source) else code
        line_at = [0] * (len(code) + 1)  # _matching names a line only in its error
        # A macro_rules! body is token trees, not items: a `mod` in it declares nothing.
        macros = [(m.end() - 1, _matching(code, m.end() - 1, line_at)) for m in _MACRO_RULES.finditer(code)
                  if m.group(0).startswith("macro_rules")]
        found = [(m, m.start()) for m in _MOD.finditer(code)
                 if _ident_start(code, m.start()) and not any(o < m.start() < c for o, c in macros)]
        inline = tuple((m.end() - 1, _matching(code, m.end() - 1, line_at), m.group(1))
                       for m, _ in found if m.group(2) == "{")
        files[path] = ModFile(module, inline)
        here = os.path.dirname(path)
        base = here if owns_dir else os.path.join(here, Path(path).stem)
        for m, at in found:
            if m.group(2) != ";":
                continue
            name, around = m.group(1), [n for o, c, n in inline if o < at < c]
            # The attributes of this item: everything since the previous item or block boundary.
            attrs = kept[max(code.rfind(ch, 0, at) for ch in ";{}") + 1:at]
            attr = _PATH_ATTR.findall(attrs)
            if attr:
                child = os.path.normpath(os.path.join(os.path.join(base, *around) if around else here, attr[-1]))
                owns = True
            else:
                d = os.path.join(base, *around)
                tried = [f"{d}/{name}.rs", f"{d}/{name}/mod.rs"]
                hit = [t for t in tried if tree.exists(t)]
                if not hit:
                    raise Unsupported(f"mod {name} in {path}: none of {', '.join(tried)}")
                child, owns = hit[0], hit[0].endswith("/mod.rs")
            if not tree.exists(child):
                raise Unsupported(f"mod {name} in {path}: no file {child}")
            todo.append((child, "::".join(p for p in (module, *around, name) if p), owns))
    return files


def _declared_test_path(tree: Tree, target: str) -> str | None:
    """The `path` a Cargo.toml `[[test]]` entry gives test target `target`, else None (cargo's
    tests/X.rs or tests/X/main.rs). Read as text, one table at a time: no TOML parser in the
    standard library this script may assume."""
    if not tree.exists("Cargo.toml"):
        return None
    for table in tree.read("Cargo.toml").split("[[test]]")[1:]:
        table = re.split(r"^\[", table, maxsplit=1, flags=re.M)[0]
        if re.search(rf'^name\s*=\s*"{re.escape(target)}"\s*$', table, re.M):
            m = re.search(r'^path\s*=\s*"([^"]+)"', table, re.M)
            return m.group(1) if m else None
    return None


def filter_refusal(tree: Tree, args: str, crates: Crates) -> tuple[str | None, str | None]:
    """(why the killer arguments' test filter does not name exactly one test, None), or
    (None, the file defining that one test). `crates` caches each crate's module tree and
    fn-name index across rows."""
    words = args.split()
    if words[:1] == ["--lib"] and len(words) == 2:
        root = "src/lib.rs"
    elif words[:1] == ["--test"] and len(words) == 3:
        declared = _declared_test_path(tree, words[1])
        roots = [r for r in ((declared,) if declared else (f"tests/{words[1]}.rs", f"tests/{words[1]}/main.rs"))
                 if tree.exists(r)]
        if not roots:
            return f"killer arguments {args!r}: no test target {words[1]}", None
        root = roots[0]
    else:
        return f"killer arguments {args!r} are not `--lib FILTER` or `--test TARGET FILTER`", None
    wanted = words[-1]
    name = wanted.rsplit("::", 1)[-1]
    try:
        if isinstance(crates.get(root), Unsupported):
            raise crates[root]  # one unreadable crate is read once, not once per row
        if root not in crates:
            try:
                mods = module_tree(tree, root)
            except Unsupported as unreadable:
                crates[root] = unreadable
                raise
            # Which crate files spell `fn <name>`, for every name at once: one pass over the
            # cached text instead of one `git grep` per row. A file with a block comment is read
            # blanked, so a comment (nested or not) between `fn` and the name is space, as
            # declarations() sees it; any other file raw, which can only over-match (a `fn x` in a
            # string or line comment), and declarations() then keeps only code.
            index: dict[str, list[str]] = {}
            for path in mods:
                source = tree.read(path)
                names = _FN.findall(blank(source)) if "/*" in source else _FN_LINE.findall(source)
                for found in sorted(set(names)):
                    index.setdefault(found, []).append(path)
            crates[root] = (mods, index)
        mods, index = crates[root]
        defs = [(p, w) for p, w, _ in _fn_paths(tree, mods, index.get(name, ()), lambda n: n == name)]
        if len(defs) == 1 and ("::" not in wanted or defs[0][0] == wanted):
            # Cargo runs every test whose path CONTAINS the filter. The filter's last segment
            # lies inside one segment of any path it matches (a module, an inline module or the
            # fn): the files where that segment could be are the only ones to read.
            near = {p for k, ps in index.items() if name in k for p in ps}
            near |= {p for p, m in mods.items() if name in m.path or any(name in n for _, _, n in m.inline)}
            runs = [p for p, _, is_test in _fn_paths(tree, mods, sorted(near), lambda n: True)
                    if is_test and wanted in p]
    except Unsupported as unreadable:
        return f"test filter {wanted}: cannot read the crate's module tree with certainty: {unreadable}", None
    if not defs:
        return f"test filter {wanted}: no fn {name} in the crate rooted at {root}", None
    if len(defs) > 1:
        return (f"test filter {wanted}: fn {name} is defined {len(defs)} times: "
                + ", ".join(f"{p} at {w}" for p, w in defs), None)
    if "::" in wanted and defs[0][0] != wanted:
        return f"test filter {wanted} does not match the module tree: fn {name} is {defs[0][0]} at {defs[0][1]}", None
    if runs != [defs[0][0]]:
        return f"test filter {wanted} matches {len(runs)} tests: {', '.join(sorted(runs))}", None
    return None, defs[0][1].rsplit(":", 1)[0]


def _fn_paths(tree: Tree, mods: dict[str, ModFile], paths, wanted) -> list[tuple[str, str, bool]]:
    """(module path, file:line, has a test attribute) of each fn in `paths` whose name `wanted`
    accepts. The attribute is read from the item's own text since the previous `;`, `{` or `}`."""
    out = []
    for path in paths:
        source, mod = tree.read(path), mods[path]
        code = None
        for d in declarations(source):
            if wanted(d.name):
                code = code if code is not None else blank(source)
                around = [n for o, c, n in mod.inline if o < d.at < c]
                attrs = code[max(code.rfind(ch, 0, d.at) for ch in ";{}") + 1:d.at]
                out.append(("::".join(p for p in (mod.path, *around, d.name) if p), f"{path}:{d.start}",
                            bool(_TEST_ATTR.search(attrs))))
    return out


def _gap_rows(tree: Tree, outcomes: list[Outcome]) -> list[tuple[dict[str, str], Outcome]]:
    """Each killer-gap row with the active obligation it belongs to, in the table's order. A row
    no active obligation uses (a slot an understudy replaced) is left out."""
    by_patch = {(o.obligation.path, Path(o.obligation.patch).name): o for o in outcomes}
    rows = []
    for row in _rows(tree.read(GAP_TABLE)):
        o = by_patch.get((row["path"], Path(row["mutant"].split(":", 1)[0]).name))
        if o is not None:
            rows.append((row, o))
    return rows


# --------------------------------------------------------------------------------------------
# Declared assertions: G7 scores a RED only at the row's declared file:line.
# --------------------------------------------------------------------------------------------
# A static tripwire for drift: it proves the declared site still holds the recorded statement
# inside the killer (or the helper the row names), in the file as the mutant run compiles it.
# It cannot prove the killer panics there; only the gate-day log does, through G7.

# `<file>:<line> <text> [stmt:<8 hex>]`, then free annotations; `[via F]` names a helper. The
# text may itself hold a `[stmt:...]`, so the marker is chosen against the judged line.
_SITE = re.compile(r"^(\S+):(\d+) (.+)$")
_STMT = re.compile(r" \[stmt:([0-9a-f]{8})\]")
_VIA = re.compile(r"\[via ([A-Za-z_]\w*)\]")


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _apply_reanchored(source: str, patch: str) -> str:
    """`source` with `patch` applied by its hunk headers. Only for a patch `_reanchor` wrote,
    whose headers name exactly where each old side sits in `source`."""
    lines = source.splitlines(keepends=True)
    edits = [(int(head[0]) - 1, int(head[1]), [text + "\n" for mark, text in hunk if mark != "-"])
             for head, hunk in zip(re.findall(r"^@@ -(\d+),(\d+) ", patch, flags=re.M), _hunks(patch))]
    text = _splice(lines, edits)
    if text is None:
        raise Unsupported("the row's patch has overlapping hunks")
    return text


def _statement(src: list[str], blanked: list[str], line: int) -> tuple[tuple[int, int], str]:
    """The statement holding 1-based `line`, as (its start (line index, column), its
    whitespace-collapsed source text), from the source lines `src` and the same lines blanked.
    Rust reports a chained call's panic at its continuation line (`.unwrap_err(),`), which
    starts no statement and can repeat inside one test: a line that opens with `.` belongs to
    the statement found by scanning back, in the blanked text, to the previous `;`, `,`, `{` or
    `}` at depth 0 (an opening `(` or `[` passed at depth 0 means the chain sits inside a call
    or list, and the scan goes on). Any other line starts its own statement at its first
    non-blank source character. From the start the text runs forward up to a `;` or `,` at
    depth 0 (kept), a closer that would take the depth below 0 (left out), or a line end at
    depth 0."""
    col = len(src[line - 1]) - len(src[line - 1].lstrip())
    j, c = (_statement_start(src, blanked, line - 1, col) if src[line - 1].lstrip().startswith(".")
            else (line - 1, col))
    depth, parts = 0, []
    for k in range(j, len(blanked)):
        text = blanked[k]
        start = c if k == j else 0
        end, done = len(text), False
        for i in range(start, len(text)):
            ch = text[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    end, done = i, True
                    break
                depth -= 1
            elif ch in ";," and depth == 0:
                end, done = i + 1, True
                break
        parts.append(src[k][start:end])
        if done or depth == 0:
            break
    return (j, c), _collapse(" ".join(parts))


def _statement_start(src: list[str], blanked: list[str], k: int, col: int) -> tuple[int, int]:
    """Where the statement holding position (line index `k`, column `col`) starts: the first
    non-blank source character after the nearest boundary before it (see `_statement`)."""
    depth, j, c = 0, k, col - 1
    while j >= 0:
        text = blanked[j]
        while c >= 0:
            ch = text[c]
            if ch in ")]" or (ch == "}" and depth):
                depth += 1
            elif ch in "([":
                depth -= 1 if depth else 0
            elif ch == "{" and depth:
                depth -= 1
            elif ch in ";,{}" and not depth:
                return _first_code(src, j, c + 1)
            c -= 1
        j -= 1
        c = len(blanked[j]) - 1 if j >= 0 else -1
    return _first_code(src, 0, 0)


def _first_code(src: list[str], j: int, c: int) -> tuple[int, int]:
    """The first non-blank source position at or after (line index `j`, column `c`)."""
    while j < len(src):
        rest = src[j][c:]
        if rest.strip():
            return j, c + len(rest) - len(rest.lstrip())
        j, c = j + 1, 0
    return j, 0


def assertion_refusal(tree: Tree, row: dict[str, str], o: Outcome, killer_file: str) -> str | None:
    """Why the row's declared_assertion would not be the site G7 matches, or None."""
    m = _SITE.match(row.get("declared_assertion", "").strip())
    marks = list(_STMT.finditer(m.group(3))) if m else []
    if not marks or not marks[0].start():
        return "declared assertion does not open with file:line, text and [stmt:<8 hex>]"
    path, line, rest = m.group(1), int(m.group(2)), m.group(3)
    site = f"declared assertion {path}:{line}"
    killer = row["declared_killer_args"].split()[-1].rsplit("::", 1)[-1]

    def judged(file: str) -> str:
        # The file the mutant run compiled: the row's own patch applied when it edits that file.
        source = tree.read(file)
        return _apply_reanchored(source, o.patch) if file == o.file and o.patch else source

    if not tree.exists(path):
        return f"{site}: no such file"
    try:
        source = judged(path)
        decls = declarations(source)
        killer_src = source if killer_file == path else judged(killer_file)
        killer_decls = [d for d in (decls if killer_file == path else declarations(killer_src)) if d.name == killer]
    except Unsupported as unreadable:
        return f"{site}: cannot read the source with certainty: {unreadable}"
    src, blanked = source.splitlines(), blank(source).splitlines()
    count = len(src)
    if not 1 <= line <= count:
        return f"{site} is outside the file's {count} lines"
    if len(killer_decls) != 1:
        return f"{site}: {killer} is declared {len(killer_decls)} times in {killer_file}"
    kdecl = killer_decls[0]
    # The digest marker is the one whose text before it is the judged line; else the first.
    wanted = _collapse(src[line - 1])
    pick = next((mk for mk in marks if _collapse(rest[:mk.start()]) == wanted), marks[0])
    text, digest, via = rest[:pick.start()], pick.group(1), _VIA.search(rest[pick.end():])
    if via:
        helper = via.group(1)
        holders = [d for d in decls if d.start <= line <= d.end]
        inner = min(holders, key=lambda d: (d.end - d.start, -d.start)) if holders else None
        if inner is None or inner.name != helper:
            return f"{site} is in {inner.name if inner else 'no fn'}, not {helper}"
        body = "\n".join(blank(killer_src).splitlines()[kdecl.start - 1:kdecl.end])
        # The fn header names the killer, never the helper; any later `F(` or `F::` is a use.
        if not re.search(rf"\b{re.escape(helper)}\s*(\(|::)", body):
            return f"{killer} does not call {helper}"
        span = inner
    else:
        if path != killer_file or not kdecl.start <= line <= kdecl.end:
            return f"{site} is not inside {killer}"
        span = kdecl
    _, statement = _statement(src, blanked, line)
    actual = hashlib.sha256(statement.encode()).hexdigest()[:8]
    if _collapse(src[line - 1]) != _collapse(text):
        return f"{site} does not carry the recorded text (statement digest there is {actual})"
    if actual != digest:
        return f"{site} statement digest is {actual}, recorded {digest}"
    # Distinct statements in the span (each line maps to the statement holding it), counted by
    # start, so a multi-line statement counts once and two identical statements count twice.
    found = dict(_statement(src, blanked, k) for k in range(span.start, span.end + 1))
    same = sum(text == statement for text in found.values())
    if same != 1:
        return f"statement at {path}:{line} occurs {same} times in {span.name}"
    return None


# --------------------------------------------------------------------------------------------
# Command line.
# --------------------------------------------------------------------------------------------

def write_manifest(tree: Tree, outcomes: list[Outcome], out: Path) -> None:
    """The re-targeted patches and a mutants manifest (scripts/ci/mutants/run_mutants.py) for
    them: one row per obligation, in the killer-gap table's row order, with that table's killer
    arguments. The freeze-day batches are cut from this file (round robin), so the order is the
    batch plan and every obligation in it is exactly the set resolved here."""
    out.mkdir(parents=True, exist_ok=True)
    lines, placed = [f"head_sha\t{tree.rev}"], set()
    for row, o in _gap_rows(tree, outcomes):
        name = Path(row["mutant"].split(":", 1)[0]).name
        d = PATCH_DIR[row["path"]]
        (out / f"{d}_{name}").write_text(o.patch or "")
        lines.append(f"{d.upper()}_{int(row['rank']):02d}\tlinux\t{d}_{name}\t{row['declared_killer_args']}")
        placed.add(id(o))
    if missing := [o.obligation for o in outcomes if id(o) not in placed]:
        raise LookupError(f"no killer-gap row for: {', '.join(f'{m.path} {m.rank}' for m in missing)}")
    (out / "manifest.tsv").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", default="HEAD", help="revision to resolve against (gate day: FROZEN)")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository (tests)")
    parser.add_argument("--manifest", type=Path, help="write re-targeted patches and a mutants manifest here")
    args = parser.parse_args(argv)

    tree = Tree(args.tree, args.root)
    try:
        return _run(tree, args)
    finally:
        if tree._scratch is not None:
            tree._scratch.cleanup()


def _run(tree: Tree, args: argparse.Namespace) -> int:
    rust_files = {p for p in tree.ls("src") if p.endswith(".rs")}
    outcomes = [resolve(tree, ob, rust_files) for ob in obligations(tree)]
    # Two slots whose rows differ can still resolve to one current function: that would count
    # one mutant as two obligations, so both are unresolved until a replacement separates them.
    seen: dict[tuple[str, int], Outcome] = {}
    for o in outcomes:
        if o.status == "unresolved":
            continue
        first = seen.setdefault((o.file, o.at), o)
        if first is not o:
            for twin in (first, o):
                twin.status = "unresolved"
                twin.detail = (f"{first.obligation.path} rank {first.obligation.rank} and "
                               f"{o.obligation.path} rank {o.obligation.rank} resolve to one function at {o.file}")
    # A row whose test filter names no test, or several, would not judge its killer; a row
    # whose declared site no longer holds its statement would have its RED scored VOID by G7.
    crates: Crates = {}
    for row, o in _gap_rows(tree, outcomes):
        if o.status == "unresolved":
            continue
        why, killer_file = filter_refusal(tree, row["declared_killer_args"], crates)
        if why or (why := assertion_refusal(tree, row, o, killer_file)):
            o.status, o.detail = "unresolved", why
    for o in outcomes:
        ob = o.obligation
        where = f"{ob.path} rank {ob.rank} {ob.qualified}"
        basis = "" if ob.note == "SAMPLE" else f"\t[{ob.note}]"
        print(f"{o.status}\t{where}\t{o.detail or o.file}{basis}")
    unresolved = sum(o.status == "unresolved" for o in outcomes)
    print(f"{len(outcomes)} framed obligations, {unresolved} framed items unresolved")
    if unresolved:
        return 1
    if args.manifest:
        write_manifest(tree, outcomes, args.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
