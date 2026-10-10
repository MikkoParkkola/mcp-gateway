#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every production construction of a caller identity is one of the allowed
sites (MIK-8286, identity-collapse).

A caller identity that names no one (an empty subject, a certificate with no
SAN URI and no CN) merges every such caller in every key built from it. The
fix refuses such identities where they are MADE, so this check pins where
they may be made: struct literals of `VerifiedIdentity`, `GrantSubject` and
`CertIdentity`, and calls of `GrantSubject::new`, in production code, each
inside an allowed function. Anything else fails, so a new source must either
go through `VerifiedIdentity::checked` / `GrantSubject::checked` or be added
here with a reason a reviewer reads.

Test code is found structurally: the module tree is walked from
`src/lib.rs` and `src/main.rs`, `#[path]` modules followed, and `#[cfg(test)]`
carried from a gated declaration to its file. Item-level `#[cfg(test)]` gates
only its own item. File names decide nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# (file, enclosing fn, construct) -> why it may build an identity directly.
ALLOWED = {
    ("src/key_server/oidc_identity.rs", "checked", "VerifiedIdentity {"): "the checked constructor",
    ("src/identity_grants.rs", "new", "GrantSubject {"): "the one literal; `checked` wraps it",
    ("src/identity_grants.rs", "checked", "GrantSubject::new("): "the checked constructor",
    ("src/mtls/identity.rs", "from_der", "CertIdentity {"): "the production parser",
}
# Grant-file RULE targets (operator input, not a caller identity): the CLI is
# the binary crate and cannot see the crate-internal `checked`.
RULE_SITES = {"src/commands/identity.rs"}
CONSTRUCTS = ("VerifiedIdentity {", "GrantSubject {", "CertIdentity {", "GrantSubject::new(")
DEFINITION = re.compile(r"\b(struct|enum|impl(<[^>]*>)?|for|trait)\s+$")


def mask(text: str) -> str:
    """`text` with comments, strings and char literals blanked (newlines kept)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif (m := re.match(r'b?r(#*)"', text[i:])) and (i == 0 or not text[i - 1].isalnum()):
            end = text.find('"' + m.group(1), i + len(m.group(0)))
            j = n if end < 0 else end + 1 + len(m.group(1))
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(re.sub(r"[^\n]", " ", text[i : j + 1]))
            i = j + 1
        elif c == "'" and (m := re.match(r"'(\\.|[^\\'])'", text[i:])):
            out.append(" " * len(m.group(0)))
            i += len(m.group(0))
        else:
            out.append(c)
            i += 1
    return "".join(out)


def block_end(code: str, start: int) -> int:
    """Index just past the item that starts at `start` (`;` or a braced body)."""
    depth = 0
    for j in range(start, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        elif code[j] == ";" and depth == 0:
            return j + 1
    return len(code)


MOD_DECL = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(?:r#)?(\w+)\s*;")
# The attribute block written directly above an item.
ATTR_BLOCK = re.compile(r"(?:#\[[^\]]*\]\s*)+$")


def gated_spans(code: str) -> list[tuple[int, int]]:
    """Spans of items under `#[cfg(test)]` (or any cfg naming `test`)."""
    spans = []
    for m in re.finditer(r"#\[cfg\(([^\]]*)\)\]", code):
        if not re.search(r"(?<!not\()\btest\b", m.group(1)):
            continue
        k = m.end()
        while (a := re.match(r"\s*#\[[^\]]*\]", code[k:])):
            k += a.end()
        spans.append((m.start(), block_end(code, k)))
    return spans


def module_files(root: Path) -> dict[Path, bool]:
    """Every module file reachable from the crate roots -> whether it is test-only."""
    seen: dict[Path, bool] = {}
    todo = [(root / "src/lib.rs", False), (root / "src/main.rs", False)]
    todo += [(p, False) for p in sorted((root / "src/bin").glob("*.rs"))]
    while todo:
        path, test = todo.pop()
        if not path.exists() or (path in seen and (seen[path] or not test)):
            continue
        seen[path] = test
        code = mask(path.read_text(encoding="utf-8"))
        gated = gated_spans(code)
        inline = [
            (im.group(1), im.end() - 1, block_end(code, im.end() - 1))
            for im in re.finditer(r"\bmod\s+(\w+)\s*\{", code)
        ]
        for m in MOD_DECL.finditer(code):
            child_test = test or any(s <= m.start() < e for s, e in gated)
            nest = [n for n, s, e in inline if s < m.start() < e]
            # The `#[path]` attribute directly above THIS declaration (the raw
            # text: masking blanks the string). Two `cfg` alternatives may
            # declare one name with different paths.
            raw = path.read_text(encoding="utf-8")
            block = ATTR_BLOCK.search(raw[: m.start()].rstrip())
            pm = re.search(r'#\[path\s*=\s*"([^"]+)"\]', block.group(0)) if block else None
            name = m.group(1)
            base = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
            for inner in nest:
                base = base / inner
            if pm:
                child = (path.parent if not nest else base) / pm.group(1)
            else:
                child = base / f"{name}.rs"
                if not child.exists():
                    child = base / name / "mod.rs"
            todo.append((child.resolve(), child_test))
    return seen


FN = re.compile(r"\bfn\s+(\w+)")


def enclosing_fn(code: str, at: int) -> str:
    """The name of the innermost `fn` whose body contains `at`, else ''."""
    best, best_start = "", -1
    for m in FN.finditer(code, 0, at):
        brace = code.find("{", m.end())
        if brace < 0 or brace > at:
            continue
        if block_end(code, m.start()) > at and m.start() > best_start:
            best, best_start = m.group(1), m.start()
    return best


IMPL = re.compile(r"\bimpl(?:<[^>{]*>)?\s+(?:[\w:<>]+\s+for\s+)?(?:[\w:]+::)?(VerifiedIdentity|GrantSubject|CertIdentity)\b[^{;]*\{")


def self_literals(code: str) -> list[tuple[int, str]]:
    """`Self {` literals inside an impl block of an identity type."""
    out = []
    for im in IMPL.finditer(code):
        start = im.end() - 1
        end = block_end(code, start)
        for m in re.finditer(r"(?<!->)(?<!-> )\bSelf\s*\{", code[start:end]):
            out.append((start + m.start(), f"{im.group(1)} {{"))
        if im.group(1) == "GrantSubject":
            for m in re.finditer(r"\bSelf::new\(", code[start:end]):
                out.append((start + m.start(), "GrantSubject::new("))
    return out


TYPES = ("VerifiedIdentity", "GrantSubject", "CertIdentity")
ALIAS = re.compile(r"\btype\s+\w+(?:<[^>]*>)?\s*=\s*(?:[\w:]+::)?(" + "|".join(TYPES) + r")\b")
# Deserialization from untrusted bytes into a caller identity, or a struct
# carrying one: each must be a listed read-back with its check site.
READ_BACK = re.compile(r"\b(?:serde_json|serde_yaml|toml|serde_yml)::from_(?:str|slice|value|reader)\b")
READ_BACKS = {
    # RULE data: operator input naming who a grant or a capability is for,
    # never a request's identity. A rule may name anyone; checking happens
    # where a request's identity is made (MIK-8286 design 2.5).
    ("src/capability/parser.rs", "parse_capability"): "rule: a definition's identity_owner",
    ("src/identity_grants.rs", "read_identity_grants_file"): "rule: the grant file",
    ("src/identity_grants/journal.rs", "parse_journal"): "rule: persisted grants",
    ("src/identity_grants_matching.rs", "parse_refusal"): "rule: grant-file error report",
    ("src/identity_grants_matching.rs", "remainder_error"): "rule: grant-file error report",
}


def carriers(texts: dict[str, str]) -> set[str]:
    """The identity types, plus every struct with a field of one (to a fixed point)."""
    found = set(TYPES)
    while True:
        grown = set(found)
        for code in texts.values():
            for sm in re.finditer(r"\bstruct\s+(\w+)[^{;]*\{", code):
                # Only types serde can build from bytes carry an identity in.
                derives = ATTR_BLOCK.search(code[: sm.start()].rstrip().removesuffix("pub").rstrip())
                if not (derives and "Deserialize" in derives.group(0)):
                    continue
                body = code[sm.end() : block_end(code, sm.end() - 1)]
                if any(re.search(r":\s*[^,]*\b" + re.escape(t) + r"\b", body) for t in found):
                    grown.add(sm.group(1))
        if grown == found:
            return found
        found = grown


def unreached(root: Path, files: dict[Path, bool]) -> list[str]:
    """Rust files under src/ the module walk never reached: fail closed."""
    return sorted(
        p.relative_to(root).as_posix()
        for p in (root / "src").rglob("*.rs")
        if p.resolve() not in files
    )


def violations(root: Path) -> list[str]:
    root = root.resolve()
    files = module_files(root)
    found = [f"{rel}: not reached from any crate root; cannot tell production from test" for rel in unreached(root, files)]
    texts = {
        path.relative_to(root).as_posix(): mask(path.read_text(encoding="utf-8"))
        for path, test in files.items()
        if not test
    }
    carrier = carriers(texts)
    names = re.compile(r"\b(" + "|".join(sorted(carrier)) + r")\b")
    for rel, code in sorted(texts.items()):
        gated = gated_spans(code)
        for m in ALIAS.finditer(code):
            if not any(s <= m.start() < e for s, e in gated):
                line = code.count("\n", 0, m.start()) + 1
                found.append(f"{rel}:{line}: a type alias of `{m.group(1)}` hides its constructions from this check")
        for m in READ_BACK.finditer(code):
            if any(s <= m.start() < e for s, e in gated):
                continue
            fn = enclosing_fn(code, m.start())
            fm = [f for f in FN.finditer(code, 0, m.start()) if f.group(1) == fn]
            # The statement holding the call, plus the fn's signature (a call
            # in tail position takes its type from the return type).
            stmt_start = max(code.rfind(";", 0, m.start()), code.rfind("{", 0, m.start())) + 1
            stmt_end = code.find(";", m.end())
            header = code[fm[-1].start() : code.find("{", fm[-1].end())] if fm else ""
            signature = header.split("->", 1)[1] if "->" in header else ""
            scope = code[stmt_start : stmt_end if stmt_end > 0 else len(code)] + signature
            if names.search(scope) and (rel, fn) not in READ_BACKS:
                line = code.count("\n", 0, m.start()) + 1
                found.append(f"{rel}:{line}: fn `{fn or '<module>'}` deserializes a caller identity (or a struct carrying one) and is not a listed read-back")
        hits = []
        for construct in CONSTRUCTS:
            if construct.endswith("{"):
                pattern = r"\b" + re.escape(construct[:-2]) + r"\s*\{"
            else:
                pattern = r"\bGrantSubject::new\("
            for m in re.finditer(pattern, code):
                before = code[max(0, m.start() - 40) : m.start()]
                if construct.endswith("{") and (
                    DEFINITION.search(before) or before.rstrip().endswith("->")
                ):
                    continue
                hits.append((m.start(), construct))
        hits += self_literals(code)
        for at, construct in sorted(hits):
            if any(s <= at < e for s, e in gated):
                continue
            if True:
                fn = enclosing_fn(code, at)
                if (rel, fn, construct) in ALLOWED or (construct == "GrantSubject::new(" and rel in RULE_SITES):
                    continue
                line = code.count("\n", 0, at) + 1
                found.append(f"{rel}:{line}: `{construct}` in fn `{fn or '<module>'}` builds an identity outside its checked constructor")
    return found


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    bad = violations(root)
    for line in bad:
        print(line)
    if bad:
        print(f"{len(bad)} identity construction(s) outside the allowed sites (MIK-8286). Build caller identities through VerifiedIdentity::checked / GrantSubject::checked.")
        return 1
    print("every identity construction is an allowed site")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
