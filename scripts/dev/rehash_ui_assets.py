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
them, so its own hash covers theirs.

    python3 -I scripts/dev/rehash_ui_assets.py
"""

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHELL = ROOT / "src/gateway/ui/shell"
SHELL_RS = ROOT / "src/gateway/ui/shell.rs"
HASHED = re.compile(r"^(?P<stem>.+?)(?:\.[0-9a-f]{12})?\.(?P<ext>css|js|json|woff2|svg|png)$")
TABLE = re.compile(r"pub\(super\) const ASSETS: &\[\(&str, &\[u8\]\)\] = &\[.*?\];", re.S)


def assets():
    """Asset files in dependency order: fonts, images and data, then CSS, then JS."""
    order = {"woff2": 0, "svg": 0, "png": 0, "json": 0, "css": 1, "js": 2}
    found = [p for p in SHELL.rglob("*") if p.is_file() and HASHED.match(p.name)]
    return sorted(found, key=lambda p: (order[HASHED.match(p.name)["ext"]], str(p)))


def rewrite_refs(stem: str, ext: str, new: str) -> None:
    """Point every reference to this asset, hashed or not, at `<new>`."""
    pattern = re.compile(r"/ui/assets/" + re.escape(stem) + r"(?:\.[0-9a-f]{12})?\." + ext + r"(?![\w.-])")
    for text in [SHELL / "index.html", *SHELL.rglob("*.css"), *SHELL.rglob("*.js")]:
        body = text.read_text()
        updated = pattern.sub(f"/ui/assets/{new}", body)
        if updated != body:
            text.write_text(updated)


def main() -> int:
    for path in assets():
        m = HASHED.match(path.name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        name = f"{m['stem']}.{digest}.{m['ext']}"
        if name != path.name:
            path.rename(path.with_name(name))
        rewrite_refs(m["stem"], m["ext"], name)
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
