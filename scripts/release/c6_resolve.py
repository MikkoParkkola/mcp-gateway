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
  4. requires `git apply --check` of the re-targeted patch against REV.
Prints one line per obligation and `N framed items unresolved`; exits 1 when N > 0.
--manifest DIR writes the re-targeted patches and a mutants manifest for the runner.
Standard library only.
"""

from __future__ import annotations

import argparse
import csv
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


def blank(source: str) -> str:
    """`source` with every comment and string, raw string, byte string and char literal
    replaced by spaces, newlines kept, so offsets and line numbers are unchanged."""
    out = list(source)
    i, n = 0, len(source)

    def wipe(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

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
            wipe(i, j + len(close))
            i = j + len(close)
        elif c == '"':  # a b"..." or c"..." prefix is just an identifier character before it
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            if j >= n:
                raise Unsupported("unterminated string")
            wipe(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'").match(source, i)
            if m:
                wipe(i, m.end())
                i = m.end()
            else:
                i += 1  # a lifetime or label: 'a
        else:
            i += 1
    return "".join(out)


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
    patched, cursor = [], 0
    for first, count, replacement in sorted(edits):
        if first < cursor:
            return "two hunks overlap"
        patched += lines[cursor:first] + replacement
        cursor = first + count
    patched_text = "".join(patched + lines[cursor:])
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
# Command line.
# --------------------------------------------------------------------------------------------

def write_manifest(tree: Tree, outcomes: list[Outcome], out: Path) -> None:
    """The re-targeted patches and a mutants manifest (scripts/ci/mutants/run_mutants.py) for
    them: one row per obligation, in the killer-gap table's row order, with that table's killer
    arguments. The freeze-day batches are cut from this file (round robin), so the order is the
    batch plan and every obligation in it is exactly the set resolved here."""
    by_patch = {(o.obligation.path, Path(o.obligation.patch).name): o for o in outcomes}
    out.mkdir(parents=True, exist_ok=True)
    lines, placed = [f"head_sha\t{tree.rev}"], set()
    for row in _rows(tree.read("docs/release/c6-gap/v4.0.0-c6-gap-table.tsv")):
        name = Path(row["mutant"].split(":", 1)[0]).name
        o = by_patch.get((row["path"], name))
        if o is None:
            continue  # a row no active obligation uses (a slot an understudy replaced)
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
