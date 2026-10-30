#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Give the web UI shell's assets their content-hashed names.

The gateway serves src/gateway/ui/shell/ assets from an exact-name table in
shell.rs, each name carrying the first 12 hex digits of the SHA-256 of its
bytes (a test holds this), so a cached copy never goes stale. After editing
an asset, run this from the repository root: it renames every asset to its
current hash, rewrites the references in index.html, the stylesheets and the scripts, and
regenerates the ASSETS table. Fonts go first because the stylesheet names
them, so its own hash covers theirs. In general every asset is hashed after
the assets it references (a module after the shell it imports); a reference
cycle is refused, and a name left not matching its bytes fails the run.

The shell's frame stylesheet, src/gateway/ui/shell-src/frame.css, is not an
asset: once its references are rewritten (and its line ends made LF), it is
copied byte for byte into index.html's <style id="frame">, whose text the
gateway's CSP allows by its hash. A document without that element is refused.

    python3 -I scripts/dev/rehash_ui_assets.py
"""

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHELL = ROOT / "src/gateway/ui/shell"
SHELL_RS = ROOT / "src/gateway/ui/shell.rs"
FRAME = ROOT / "src/gateway/ui/shell-src/frame.css"
FRAME_STYLE = re.compile(r'(<style id="frame">)(.*?)(</style>)', re.S)
HASHED = re.compile(r"^(?P<stem>.+?)(?:\.[0-9a-f]{12})?\.(?P<ext>css|js|json|woff2|svg|png)$")
TABLE = re.compile(r"pub\(super\) const ASSETS: &\[\(&str, &\[u8\]\)\] = &\[.*?\];", re.S)


def assets():
    """Asset files, sorted by path (the ASSETS table's order)."""
    return sorted((p for p in SHELL.rglob("*") if p.is_file() and HASHED.match(p.name)), key=str)


def ref_pattern(stem: str, ext: str) -> re.Pattern:
    """A reference to this asset, hashed or not."""
    return re.compile(r"/ui/assets/" + re.escape(stem) + r"(?:\.[0-9a-f]{12})?\." + ext + r"(?![\w.-])")


def in_dependency_order(found):
    """`found` ordered so each asset comes after every asset it references.

    An asset's hash covers the names it references, so it is hashed only once
    they are final; hashing in path order instead left a module that sorts
    before the shell and imports it with a stale name. A cycle has no such
    order and is refused.
    """
    keys = {p: (HASHED.match(p.name)["stem"], HASHED.match(p.name)["ext"]) for p in found}
    text = {p: p.read_text(errors="ignore") if keys[p][1] in ("css", "js") else "" for p in found}
    # A file naming itself is a cycle too: its name could never match its bytes.
    deps = {p: {q for q in found if ref_pattern(*keys[q]).search(text[p])} for p in found}
    ordered, done, visiting = [], set(), []

    def visit(p):
        if p in done:
            return
        if p in visiting:
            chain = " -> ".join(q.name for q in visiting[visiting.index(p):] + [p])
            raise SystemExit(f"rehash_ui_assets: reference cycle: {chain}")
        visiting.append(p)
        for q in sorted(deps[p], key=str):
            visit(q)
        visiting.pop()
        done.add(p)
        ordered.append(p)

    for p in sorted(found, key=str):
        visit(p)
    return ordered


def rewrite_refs(stem: str, ext: str, new: str) -> None:
    """Point every reference to this asset, hashed or not, at `<new>`."""
    pattern = ref_pattern(stem, ext)
    for text in [SHELL / "index.html", FRAME, *SHELL.rglob("*.css"), *SHELL.rglob("*.js")]:
        body = text.read_text()
        updated = pattern.sub(f"/ui/assets/{new}", body)
        if updated != body:
            text.write_text(updated)


def stale_names():
    """Assets whose name does not carry the hash of their bytes."""
    out = []
    for path in assets():
        m = HASHED.match(path.name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        if path.name != f"{m['stem']}.{digest}.{m['ext']}":
            out.append(path.name)
    return out


def inline_frame() -> None:
    """Copy frame.css, LF line ends, into the document's frame element."""
    frame = FRAME.read_bytes().replace(b"\r\n", b"\n").decode()
    FRAME.write_bytes(frame.encode())
    document = SHELL / "index.html"
    body = document.read_text()
    updated = FRAME_STYLE.sub(lambda m: m[1] + frame + m[3], body, count=1)
    if updated != body:
        document.write_text(updated)


def main() -> int:
    # Refused before anything moves: the frame has nowhere to go.
    if len(FRAME_STYLE.findall((SHELL / "index.html").read_text())) != 1:
        print('rehash_ui_assets: index.html needs exactly one <style id="frame"></style>', file=sys.stderr)
        return 1
    for path in in_dependency_order(assets()):
        m = HASHED.match(path.name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        name = f"{m['stem']}.{digest}.{m['ext']}"
        if name != path.name:
            path.rename(path.with_name(name))
        rewrite_refs(m["stem"], m["ext"], name)
    inline_frame()
    # The order above makes this hold; checking it keeps a future mistake loud.
    stale = stale_names()
    if stale:
        print("rehash_ui_assets: names no longer match their bytes: " + ", ".join(stale), file=sys.stderr)
        return 1
    rows = []
    for path in assets():
        rel = path.relative_to(SHELL).as_posix()
        rows.append(f'    (\n        "{path.name}",\n        include_bytes!("shell/{rel}"),\n    ),')
    table = "pub(super) const ASSETS: &[(&str, &[u8])] = &[\n" + "\n".join(rows) + "\n];"
    source = SHELL_RS.read_text()
    if not TABLE.search(source):
        print("rehash_ui_assets: ASSETS table not found in shell.rs", file=sys.stderr)
        return 1
    SHELL_RS.write_text(TABLE.sub(lambda _: table, source, count=1))
    for path in assets():
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
