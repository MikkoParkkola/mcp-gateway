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
from urllib.parse import urlsplit

DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "src/registry/server_registry_entries.rs"
ENTRY_RE = re.compile(r"RegistryEntry \{(.*?)\n    \},", re.S)
# `\s*` around the value: rustfmt moves a long string onto the next line.
FIELD_RE = {
    "name": re.compile(r'\bname:\s*"([^"]*)"'),
    "command": re.compile(r'\bcommand:\s*"([^"]*)"'),
    "url": re.compile(r'\bdefault_url:\s*"([^"]*)"'),
    "auth": re.compile(r"\bauth:\s*Auth::(\w+)"),
}
# Exact versions only: a range or a dist-tag resolves to something new later.
# npm reads `pkg@1` and `pkg@1.2` as ranges, so npm needs all three parts;
# `uvx pkg@1.2` pins `==1.2` exactly.
VERSION_RE = {
    "npm": re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$"),
    "pypi": re.compile(r"^\d+(\.\d+)+([.-]?(a|b|rc|post|dev)\d+)*$"),
}


def parse_entries(source: str) -> list[dict[str, str]]:
    """Every `RegistryEntry { .. }` block; one that yields no name is kept
    with a placeholder so `classify` fails it instead of the check skipping it."""
    entries = []
    for index, block in enumerate(ENTRY_RE.findall(source)):
        entry = {}
        for key, rx in FIELD_RE.items():
            m = rx.search(block)
            if m:
                entry[key] = m.group(1)
        if "name" not in entry:
            entry = {"name": f"<entry #{index + 1}>", "unparsed": "1"}
        entries.append(entry)
    return entries


def split_pinned(spec: str, kind: str) -> tuple[str, str] | None:
    """`@scope/pkg@1.2.3` -> (`@scope/pkg`, `1.2.3`); None when unpinned."""
    at = spec.rfind("@")
    if at <= 0:
        return None
    pkg, version = spec[:at], spec[at + 1 :]
    return (pkg, version) if VERSION_RE[kind].match(version) else None


def classify(entry: dict[str, str]) -> tuple[str, str, str] | str:
    """Return (kind, target, version) to probe, or an error string."""
    if entry.get("unparsed"):
        return "entry could not be parsed (no name field found)"
    if entry.get("url"):
        # The registry writes no client_id for an OAuth entry, so the endpoint
        # must offer dynamic client registration; a header entry must refuse
        # an unauthenticated request rather than serve it.
        kind = {"OAuth": "http-oauth", "Header": "http-header"}.get(entry.get("auth", ""), "http")
        return (kind, entry["url"], "")
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
    pinned = split_pinned(rest[0], kind)
    if pinned is None:
        return f"'{rest[0]}' is not pinned to an exact version (<package>@<x.y.z>)"
    return (kind, pinned[0], pinned[1])


def fetch(url: str, body: bytes | None = None) -> tuple[int, bytes]:
    """GET `url`, or POST `body` as JSON when one is given."""
    last: Exception | None = None
    headers = {"User-Agent": "mcp-gateway-registry-check"}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    for attempt in range(3):
        req = urllib.request.Request(url, data=body, headers=headers)
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


# An MCP `initialize` with no credential, for a header entry whose GET is 405.
UNAUTHENTICATED_INITIALIZE = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcp-gateway-registry-check", "version": "1"},
    },
}).encode()


def well_known(base: str, suffix: str) -> str:
    """RFC 8414 path insertion, as `src/oauth/metadata.rs` `well_known_url` builds it."""
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.netloc}/.well-known/{suffix}{parts.path.rstrip('/')}"


def fetch_json(url: str) -> dict:
    try:
        status, body = fetch(url)
        return json.loads(body) if status == 200 else {}
    except (RuntimeError, ValueError):
        return {}


def registration_endpoint(url: str) -> str | None:
    """Discover the way the gateway's backend OAuth client does
    (`src/oauth/client/mod.rs` `initialize`): protected-resource metadata at
    the resource's origin, its FIRST authorization server (else the origin),
    that server's RFC 8414 metadata with its issuer checked, then the
    `registration_endpoint` the gateway registers at when it has no client_id."""
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    servers = fetch_json(well_known(origin, "oauth-protected-resource")).get("authorization_servers") or []
    server, advertised = (servers[0], True) if servers else (origin, False)
    meta = fetch_json(well_known(server, "oauth-authorization-server"))
    issuer = meta.get("issuer", "")
    if (issuer if advertised else issuer.rstrip("/")) != server:
        return None
    return meta.get("registration_endpoint")


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
            if not files:
                return f"PyPI {target}=={version} has no distribution files"
            if all(f.get("yanked") for f in files):
                return f"PyPI {target}=={version} is yanked"
            return None
        status, _ = fetch(target)
        if status in (404, 410):
            return f"{target}: HTTP {status}"
        if kind == "http-header" and status == 405:
            # A streamable endpoint need not serve GET, so a 405 says nothing
            # about credentials: ask the way a client would (MIK-7817).
            status, _ = fetch(target, UNAUTHENTICATED_INITIALIZE)
            if status in (404, 405, 410):
                return f"{target}: HTTP {status} to POST as well; it does not serve MCP at this URL"
        if kind == "http-header" and status not in (401, 403):
            return f"{target}: HTTP {status} without a credential (a header entry must refuse it)"
        if kind == "http-oauth" and not registration_endpoint(target):
            return f"{target}: no dynamic client registration in its OAuth metadata"
        return None
    except RuntimeError as e:
        return f"{target}: {e}"


def main(argv: list[str]) -> int:
    offline = "--offline" in argv
    args = [a for a in argv[1:] if a != "--offline"]
    path = Path(args[0]) if args else DEFAULT_SOURCE
    source = path.read_text()
    entries = parse_entries(source)
    if not entries:
        print(f"FAIL: no registry entries parsed from {path}")
        return 1
    # A block whose closing brace is indented differently is not matched by
    # ENTRY_RE; count the openings so it fails rather than goes unchecked.
    declared = len(re.findall(r"^\s*RegistryEntry \{", source, re.M))
    if declared != len(entries):
        print(f"FAIL: {declared} RegistryEntry blocks in {path}, {len(entries)} parsed")
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
