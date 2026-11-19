#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Check the Homebrew formula the release writes installs this release's man page.

    python3 scripts/release/check_formula.py FORMULA VERSION REPO SHA256SUMS

The formula must declare `resource "man-page"` whose url is exactly this release's mcp-gateway.1 asset and whose
sha256 is exactly mcp-gateway.1's line in SHA256SUMS.txt, and must install it with
`resource("man-page").stage { man1.install "mcp-gateway.1" }`. Exit 0 when it does, 1 with one line per fault.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

INSTALL = 'resource("man-page").stage { man1.install "mcp-gateway.1" }'


def resource_block(text: str, name: str) -> str | None:
    match = re.search(rf'resource "{re.escape(name)}" do\n(.*?)\n\s*end\n', text, re.S)
    return match.group(1) if match else None


def problems(formula: str, version: str, repo: str, sums: str) -> list[str]:
    found = []
    url = f"https://github.com/{repo}/releases/download/v{version}/mcp-gateway.1"
    page_sha = next((p[0] for p in (l.split() for l in sums.splitlines()) if len(p) == 2 and p[1] == "mcp-gateway.1"), None)
    block = resource_block(formula, "man-page")
    if block is None:
        found.append('no resource "man-page"')
    else:
        got_url = re.search(r'url "([^"]*)"', block)
        got_sha = re.search(r'sha256 "([^"]*)"', block)
        if not got_url or got_url.group(1) != url:
            found.append(f'resource "man-page": url is not {url}')
        if not got_sha or page_sha is None or got_sha.group(1) != page_sha:
            found.append("resource \"man-page\": sha256 is not mcp-gateway.1's line in SHA256SUMS.txt")
    if INSTALL not in formula:
        found.append(f"no {INSTALL}")
    return found


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 4:
        print("usage: check_formula.py FORMULA VERSION REPO SHA256SUMS", file=sys.stderr)
        return 2
    found = problems(Path(args[0]).read_text(encoding="utf-8"), args[1], args[2], Path(args[3]).read_text(encoding="utf-8"))
    for line in found:
        print(line)
    if not found:
        print(f"{args[0]}: installs the man page of v{args[1]}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
