#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when a built-in registry entry points at something that does not exist.

`mcp-gateway add <name>` writes whatever src/registry/server_registry.rs says.
On 2026-10-02, 30 of its 45 npx packages were 404 on npm and 7 more were
deprecated, and nothing noticed. Every entry must now be one of:

- `npx -y <package>@<exact version> [args]`: the version exists on npm and is
  not deprecated;
- `uvx <package>@<exact version> [args]`: the release exists on PyPI and is not
  yanked;
- an HTTP entry whose default URL answers (any status but 404/410/5xx; hosted
  MCP endpoints answer 401/400/405 to an unauthenticated GET).

Anything else, including an unpinned package or an unknown launcher, fails.
Network: one request per entry, retried; a registry outage fails the job
rather than passing it.

Usage: check-registry-packages.py [--offline] [path-to-server_registry.rs]

--offline applies the pin and launcher rules without any network lookup; it
runs on every pull request. The live lookups run where the registry changes,
on pushes and daily (.github/workflows/registry-packages.yml).
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "src/registry/server_registry_entries.rs"
ENTRY_RE = re.compile(r"RegistryEntry \{(.*?)\n    \},", re.S)
FIELD_RE = {
    "name": re.compile(r'\bname: "([^"]*)"'),
    "command": re.compile(r'\bcommand: "([^"]*)"'),
    "url": re.compile(r'\bdefault_url: "([^"]*)"'),
}
# Exact versions only: a range or a dist-tag resolves to something new later.
VERSION_RE = re.compile(r"^\d+(\.\d+)*([-.+][0-9A-Za-z.-]+)?$")


def parse_entries(source: str) -> list[dict[str, str]]:
    entries = []
    for block in ENTRY_RE.findall(source):
        entry = {}
        for key, rx in FIELD_RE.items():
            m = rx.search(block)
            if m:
                entry[key] = m.group(1)
        if "name" in entry:
            entries.append(entry)
    return entries


def split_pinned(spec: str) -> tuple[str, str] | None:
    """`@scope/pkg@1.2.3` -> (`@scope/pkg`, `1.2.3`); None when unpinned."""
    at = spec.rfind("@")
    if at <= 0:
        return None
    pkg, version = spec[:at], spec[at + 1 :]
    return (pkg, version) if VERSION_RE.match(version) else None


def classify(entry: dict[str, str]) -> tuple[str, str, str] | str:
    """Return (kind, target, version) to probe, or an error string."""
    if entry.get("url"):
        return ("http", entry["url"], "")
    tokens = entry.get("command", "").split()
    if not tokens:
        return "no command and no default_url"
    if tokens[0] == "npx":
        rest = [t for t in tokens[1:] if t not in ("-y", "--yes")]
        kind = "npm"
    elif tokens[0] == "uvx":
        rest = tokens[1:]
        kind = "pypi"
    else:
        return f"unknown launcher '{tokens[0]}' (expected npx, uvx or an HTTP url)"
    if not rest or rest[0].startswith("-"):
        return "launcher has no package argument"
    pinned = split_pinned(rest[0])
    if pinned is None:
        return f"'{rest[0]}' is not pinned to an exact version (<package>@<x.y.z>)"
    return (kind, pinned[0], pinned[1])


def fetch(url: str) -> tuple[int, bytes]:
    last: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers={"User-Agent": "mcp-gateway-registry-check"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return e.code, b""
            last = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"unreachable after 3 attempts: {last}")


def probe(kind: str, target: str, version: str) -> str | None:
    """Return None when the target resolves, else the reason it does not."""
    try:
        if kind == "npm":
            status, body = fetch(f"https://registry.npmjs.org/{target}/{version}")
            if status != 200:
                return f"npm {target}@{version}: HTTP {status}"
            deprecated = json.loads(body).get("deprecated")
            return f"npm {target}@{version} is deprecated: {deprecated}" if deprecated else None
        if kind == "pypi":
            status, body = fetch(f"https://pypi.org/pypi/{target}/{version}/json")
            if status != 200:
                return f"PyPI {target}=={version}: HTTP {status}"
            files = json.loads(body).get("urls", [])
            if files and all(f.get("yanked") for f in files):
                return f"PyPI {target}=={version} is yanked"
            return None
        status, _ = fetch(target)
        return f"{target}: HTTP {status}" if status in (404, 410) else None
    except RuntimeError as e:
        return f"{target}: {e}"


def main(argv: list[str]) -> int:
    offline = "--offline" in argv
    args = [a for a in argv[1:] if a != "--offline"]
    path = Path(args[0]) if args else DEFAULT_SOURCE
    entries = parse_entries(path.read_text())
    if not entries:
        print(f"FAIL: no registry entries parsed from {path}")
        return 1
    failures = []
    for entry in entries:
        plan = classify(entry)
        if isinstance(plan, str):
            reason = plan
        else:
            reason = None if offline else probe(*plan)
        if reason:
            failures.append(f"{entry['name']}: {reason}")
    for line in failures:
        print(f"FAIL {line}")
    verb = "are pinned (offline)" if offline else "resolve"
    print(f"{len(entries) - len(failures)}/{len(entries)} registry entries {verb}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
