#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline checks that check-registry-packages.py refuses what it claims to."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "crp", Path(__file__).with_name("check-registry-packages.py")
)
crp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crp)

SNIPPET = """
static REGISTRY: &[RegistryEntry] = &[
    RegistryEntry {
        name: "a",
        command: "npx -y @scope/pkg@1.2.3 --flag",
        transport: Transport::Stdio,
    },
    RegistryEntry {
        name: "b",
        command: "",
        transport: Transport::Http {
            default_url: "https://example.com/mcp",
        },
    },
];
"""


def check(entry, expected):
    got = crp.classify(entry)
    assert (isinstance(got, str) and isinstance(expected, str) and expected in got) or got == expected, (
        entry,
        got,
        expected,
    )


entries = crp.parse_entries(SNIPPET)
assert [e["name"] for e in entries] == ["a", "b"], entries
check(entries[0], ("npm", "@scope/pkg", "1.2.3"))
check(entries[1], ("http", "https://example.com/mcp", ""))
check({"name": "x", "command": "npx -y @scope/pkg"}, "not pinned")
check({"name": "x", "command": "npx -y pkg@latest"}, "not pinned")
check({"name": "x", "command": "npx -y pkg@^1.2.0"}, "not pinned")
check({"name": "x", "command": "uvx mcp-server-git@2026.8.18"}, ("pypi", "mcp-server-git", "2026.8.18"))
check({"name": "x", "command": "uvx mcp-server-git"}, "not pinned")
check({"name": "x", "command": "docker run img:1"}, "unknown launcher")
check({"name": "x", "command": ""}, "no command")
check({"name": "x", "command": "npx -y"}, "no package")
check({"name": "x", "command": "npx -y 0.0.83@0.0.83"}, ("npm", "0.0.83", "0.0.83"))
check({"name": "x", "command": "npx -y @playwright/mcp@0.0.83-beta.1"}, ("npm", "@playwright/mcp", "0.0.83-beta.1"))

# Probe verdicts, with the network replaced.
answers = {}
crp.fetch = lambda url, body=None: answers[("POST", url) if body is not None else url]
answers["https://registry.npmjs.org/p/1.0.0"] = (404, b"")
assert "HTTP 404" in crp.probe("npm", "p", "1.0.0")
answers["https://registry.npmjs.org/p/1.0.0"] = (200, json.dumps({"deprecated": "gone"}).encode())
assert "deprecated" in crp.probe("npm", "p", "1.0.0")
answers["https://registry.npmjs.org/p/1.0.0"] = (200, b"{}")
assert crp.probe("npm", "p", "1.0.0") is None
answers["https://pypi.org/pypi/q/1.0/json"] = (200, json.dumps({"urls": [{"yanked": True}]}).encode())
assert "yanked" in crp.probe("pypi", "q", "1.0")
answers["https://pypi.org/pypi/q/1.0/json"] = (404, b"")
assert "HTTP 404" in crp.probe("pypi", "q", "1.0")
for status, ok in ((401, True), (405, True), (400, True), (404, False), (410, False)):
    answers["https://h/mcp"] = (status, b"")
    assert (crp.probe("http", "https://h/mcp", "") is None) == ok, status


# Header and OAuth entries.
answers["https://h/mcp"] = (200, b"")
assert "without a credential" in crp.probe("http-header", "https://h/mcp", "")
answers["https://h/mcp"] = (401, b"")
assert crp.probe("http-header", "https://h/mcp", "") is None
# MIK-7817: a GET answered 405 says nothing about credentials (a streamable
# endpoint need not serve GET), so the check asks with an unauthenticated POST.
answers["https://h/mcp"] = (405, b"")
for post, verdict in ((401, None), (403, None), (200, "without a credential"), (405, "does not serve MCP")):
    answers[("POST", "https://h/mcp")] = (post, b"")
    got = crp.probe("http-header", "https://h/mcp", "")
    assert got == verdict if verdict is None else verdict in (got or ""), (post, got)
answers["https://h/.well-known/oauth-protected-resource"] = (404, b"")
answers["https://h/.well-known/oauth-authorization-server"] = (404, b"")
assert "no dynamic client registration" in crp.probe("http-oauth", "https://h/mcp", "")
# Discovery mirrors the runtime: origin PRM, first server, RFC 8414 path insertion, issuer checked.
answers["https://h/.well-known/oauth-protected-resource"] = (200, json.dumps({"authorization_servers": ["https://as/x", "https://other"]}).encode())
answers["https://as/.well-known/oauth-authorization-server/x"] = (200, json.dumps({"issuer": "https://as/x", "registration_endpoint": "https://as/register"}).encode())
assert crp.probe("http-oauth", "https://h/mcp", "") is None
answers["https://as/.well-known/oauth-authorization-server/x"] = (200, json.dumps({"issuer": "https://evil", "registration_endpoint": "https://as/register"}).encode())
assert "no dynamic client registration" in crp.probe("http-oauth", "https://h/mcp", ""), "issuer mismatch must fail"
check({"name": "x", "url": "https://h/mcp", "auth": "OAuth"}, ("http-oauth", "https://h/mcp", ""))
check({"name": "x", "url": "https://h/mcp", "auth": "Header"}, ("http-header", "https://h/mcp", ""))
assert crp.parse_entries('    RegistryEntry {\n        name: "o",\n        auth: Auth::OAuth,\n    },')[0]["auth"] == "OAuth"
# npm ranges are not pins; PyPI two-part versions are.
check({"name": "x", "command": "npx -y pkg@1"}, "not pinned")
check({"name": "x", "command": "npx -y pkg@1.2"}, "not pinned")
check({"name": "x", "command": "uvx pkg@1.2"}, ("pypi", "pkg", "1.2"))
check({"name": "x", "command": "uvx pkg@1.2rc1"}, ("pypi", "pkg", "1.2rc1"))
# A wrapped name is still parsed; a block with no name is failed, not skipped.
wrapped = crp.parse_entries('    RegistryEntry {\n        name:\n            "w",\n        command: "npx -y p@1.0.0",\n    },')
assert wrapped[0]["name"] == "w", wrapped
nameless = crp.parse_entries('    RegistryEntry {\n        command: "npx -y p@1.0.0",\n    },')
check(nameless[0], "could not be parsed")
answers["https://pypi.org/pypi/q/1.0/json"] = (200, json.dumps({"urls": []}).encode())
assert "no distribution files" in crp.probe("pypi", "q", "1.0")


# A block the entry pattern cannot match fails the whole check.
import tempfile
with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as drift:
    drift.write('    RegistryEntry {\n        name: "a",\n        command: "npx -y a@1.0.0",\n    },\n'
                '    RegistryEntry {\n        name: "b",\n        command: "npx -y b@1.0.0",\n      },\n')
assert crp.main(["x", "--offline", drift.name]) == 1


def unreachable(url):
    raise RuntimeError("down")


crp.fetch = unreachable
assert "down" in crp.probe("http", "https://h/mcp", "")
print("check-registry-packages self-test: ok")
