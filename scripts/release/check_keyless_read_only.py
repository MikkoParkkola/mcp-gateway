#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail if an installed config would refuse a read-only tool called without a key.

MIK-7752 AC3. A modern `tools/call` with no idempotency key is refused only
when `server.idempotency_key` is `required` and the (server, tool) pair is not
in `idempotency.read_only_tools` (src/gateway/meta_mcp/admission.rs,
`admit_operation`). This check enumerates every tool the live gateway serves
for the installed config and applies that rule to each.

"Read-only" here is the served `readOnlyHint`: the backend's own, or else the
gateway's name-based inference (src/backend/annotations.rs). It is a check-time
signal only: admission never trusts annotations (ADR-012 A1,
src/config/features/idempotency.rs), which is exactly why a read-only tool can
be refused and why this check exists.

    # 1. capture the catalog from the running gateway (read-only list calls)
    python3 scripts/release/check_keyless_read_only.py capture \
        --url http://127.0.0.1:39401/mcp --out catalog.json
    # 2. grade it against the installed config, as declared and as `required`
    python3 scripts/release/check_keyless_read_only.py check \
        --config servers.yaml --catalog catalog.json --mode declared
    python3 scripts/release/check_keyless_read_only.py check \
        --config servers.yaml --catalog catalog.json --mode required

The declared mode is the YAML value unless MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY
overrides it: from this process's environment, the config's `env_files`, or
any `--env-file` (pass the files the launcher sources), with the gateway's
precedence. Pass `--token-file` to capture from a gateway with auth enabled.
The `required` pass
does not depend on the declared mode.

The env layer is graded fail-closed: a plain `KEY=optional|required` is read;
any other env line or variable naming an idempotency setting makes the check
fail as unverifiable. A default routing profile other than `allow_tools: ['*']`
also fails, since the capture sees only that profile's view.

A `--token-file` given to `check` names the key the catalog was captured
with: a key carrying `allowed_tools` or `denied_tools` fails, as its view is
not every tool, and a key absent from `auth.api_keys` fails as unverifiable.
With auth enabled, `check` without `--token-file` fails as unverifiable.

Limits: capability tools exposed only in another capability state are not
captured. A backend whose tools/list drain stopped early (page cap or budget,
src/backend/list_drain.rs) serves a partial catalog that `gateway_list_tools`
does not flag, so its missing tools go unchecked. Backend `enabled` flags are
read from the YAML only.

Exit 0 when every read-only tool is admitted keyless and every enabled backend
was enumerated; 1 with one line per problem otherwise; 2 on unreadable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import yaml

REVISION = "2025-11-25"
ENV_KEY = "MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY"


# The env layer is graded fail-closed, not parsed: only a plain assignment of
# the mode is understood. Any other line naming an idempotency setting (other
# dotenv spellings, `MCP_GATEWAY_IDEMPOTENCY__READ_ONLY_TOOLS`) makes the grade
# unverifiable. The key name must appear literally for dotenv to set it, so
# this cannot miss an assignment whatever the grammar.
# Exact MCP_GATEWAY_ prefix, case-free segments after it (OverlayEnv::data).
PLAIN = re.compile(r"^(?:export\s+)?MCP_GATEWAY_(?i:SERVER__IDEMPOTENCY_KEY)\s*=\s*(['\"]?)"
                   r"((?i:optional|required))\1\s*(?:#.*)?$")
# Routing keys too: they change which tools a capture can see.
# The gateway lowercases path segments after MCP_GATEWAY_, so matching is
# case-insensitive. ENV_FILES and HOME change which env files are read.
# Auth keys too: an env-set key can filter what the capture key sees.
TOUCHES = ("MCP_GATEWAY_IDEMPOTENCY", ENV_KEY, "MCP_GATEWAY_ENV_FILES",
           "MCP_GATEWAY_DEFAULT_ROUTING_PROFILE", "MCP_GATEWAY_ROUTING_PROFILES",
           "MCP_GATEWAY_AUTH")
HOME = re.compile(r"^(?:export\s+)?HOME\s*=")


class Unverifiable(Exception):
    """The env layer sets idempotency config in a form this check does not model."""


def env_value(path: Path) -> str | None:
    found = None
    if path.is_file():
        for line in path.read_text().splitlines():
            text = line.strip()
            if HOME.match(text):
                raise Unverifiable(f"{path}: assigns HOME, which moves later env-file paths")
            if text.startswith("#") or not any(t in text.upper() for t in TOUCHES):
                continue
            if not (match := PLAIN.match(text)):
                raise Unverifiable(f"{path}: env line sets config this check cannot grade")
            found = match.group(2).lower()
    return found


def env_override(config: dict, launcher_files: list[Path]) -> str | None:
    """The idempotency mode the gateway's env layer would see.

    As EnvOverlay::resolve (src/config/env_overlay.rs): a config `env_files`
    assignment wins, later file over earlier; otherwise the process
    environment, which the launcher builds by sourcing `launcher_files` over
    what it inherited (this process's environment stands in for that).
    """
    for key in os.environ:
        if key != ENV_KEY and key.upper().startswith(TOUCHES):
            raise Unverifiable(f"process env sets {key}, which this check cannot grade")
    process = os.environ.get(ENV_KEY)
    for path in launcher_files:
        if (value := env_value(path)) is not None:
            process = value
    overlay = None
    for entry in config.get("env_files") or []:
        if (value := env_value(Path(os.path.expanduser(str(entry))))) is not None:
            overlay = value
    return overlay if overlay is not None else process


def profile_problems(config: dict) -> list[str]:
    """A capture sees the default routing profile's view; it must be unfiltered."""
    # As the gateway: an absent name is "default", an undefined profile allows all.
    name = config.get("default_routing_profile") or "default"
    profile = (config.get("routing_profiles") or {}).get(name)
    if profile is None:
        return []
    if not isinstance(profile, dict) or {k: v for k, v in profile.items() if k != "description"} != {"allow_tools": ["*"]}:
        return [f"default routing profile {name!r} filters tools: a capture cannot see every tool"]
    return []


def key_problems(config: dict, token: str | None) -> list[str]:
    """A capture made with a key sees that key's view; one that filters tools hides some."""
    auth = config.get("auth") or {}
    if token is None:
        if auth.get("enabled"):
            raise Unverifiable("auth is enabled: pass the capture key with --token-file")
        return []
    if token == auth.get("bearer_token"):
        return []
    digest = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    for entry in auth.get("api_keys") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("key") != token and entry.get("key_sha256") != digest:
            continue
        if entry.get("allowed_tools") is not None or entry.get("denied_tools"):
            return [f"capture key {entry.get('name')!r} filters tools (allowed_tools or "
                    "denied_tools): a capture cannot see every tool"]
        return []
    raise Unverifiable("the capture key is not in auth.api_keys: its tool filters cannot be checked")


def keyless_refused(mode: str, read_only: set[tuple[str, str]], server: str, tool: str) -> bool:
    # ponytail: mirrors admit_operation's keyless branch (admission.rs) in Python;
    # if that rule gains a condition, this copy drifts. Upgrade path: a gateway
    # subcommand that answers admission for a (server, tool) from the real code.
    return mode == "required" and (server, tool) not in read_only


def problems(config: dict, catalog: dict[str, list[dict]], mode: str,
             override: str | None = None) -> tuple[list[str], dict]:
    server = config.get("server") or {}
    declared = override if override is not None else server.get("idempotency_key", "optional")
    if declared not in ("optional", "required"):
        raise ValueError(f"server.idempotency_key: unknown mode {declared!r}")
    effective = declared if mode == "declared" else mode
    read_only = {
        (t["server"], t["tool"])
        for t in ((config.get("idempotency") or {}).get("read_only_tools") or [])
    }
    out: list[str] = []
    backends = config.get("backends") or {}
    for name, spec in sorted(backends.items()):
        if isinstance(spec, dict) and spec.get("enabled") is False:
            continue
        if name not in catalog:
            out.append(f"{name}: enabled backend not enumerated (listing failed or absent)")
    total = hinted = 0
    for srv, tools in sorted(catalog.items()):
        for tool in tools:
            total += 1
            if (tool.get("annotations") or {}).get("readOnlyHint") is True:
                hinted += 1
                if keyless_refused(effective, read_only, srv, tool["name"]):
                    out.append(f"{srv}:{tool['name']}: read-only tool refused without a key ({effective})")
    if total == 0:
        out.append("catalog has no tools: nothing was enumerated")
    stats = {"mode": effective, "declared": declared, "tools": total, "read_only": hinted,
             "listed_read_only": len(read_only)}
    return out, stats


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: it would carry the bearer key to another origin."""

    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Session:
    """Minimal streamable-HTTP MCP client: initialize, then tools/call."""

    def __init__(self, url: str, token: str | None = None):
        self.url, self.token, self.sid, self.next_id = url, token, None, 0
        self.call("initialize", {"protocolVersion": REVISION, "capabilities": {},
                                 "clientInfo": {"name": "mcp-gateway-release-check", "version": "1"}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def post(self, body: dict) -> dict | None:
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
            headers["MCP-Protocol-Version"] = REVISION
        req = urllib.request.Request(self.url, json.dumps(body).encode(), headers)
        with OPENER.open(req, timeout=120) as resp:
            self.sid = resp.headers.get("Mcp-Session-Id") or self.sid
            text = resp.read().decode()
        if "id" not in body or not text.strip():
            return None
        if text.lstrip().startswith("{"):
            return json.loads(text)
        frames = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:")]
        return next(f for f in frames if f.get("id") == body["id"])

    def call(self, method: str, params: dict) -> dict:
        self.next_id += 1
        reply = self.post({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        if "error" in reply:
            raise RuntimeError(f"{method}: {reply['error']}")
        return reply["result"]

    def meta(self, tool: str, args: dict) -> dict:
        result = self.call("tools/call", {"name": tool, "arguments": args})
        if result.get("isError"):
            raise RuntimeError(f"{tool} {args}: {result}")
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])


def capture(url: str, token: str | None = None) -> tuple[dict[str, list[dict]], int]:
    # Every server, not the aggregate tool list: that covers only backends
    # already started. A per-server list starts an idle backend, as a client
    # call would. A server that fails to list is left out, so the check
    # reports it as not enumerated; one that lists no tools is recorded empty.
    session = Session(url, token)
    catalog: dict[str, list[dict]] = {}
    failed = 0
    for server in sorted(s["name"] for s in session.meta("gateway_list_servers", {})["servers"]):
        try:
            catalog[server] = session.meta("gateway_list_tools", {"server": server})["tools"]
        except (RuntimeError, OSError) as err:
            print(f"{server}: list failed: {err}", file=sys.stderr)
            failed += 1
    return catalog, failed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture")
    cap.add_argument("--url", required=True)
    cap.add_argument("--out", required=True, type=Path)
    cap.add_argument("--token-file", type=Path,
                     help="bearer key for a gateway with auth enabled (an all-backends operator)")
    chk = sub.add_parser("check")
    chk.add_argument("--config", required=True, type=Path)
    chk.add_argument("--catalog", required=True, type=Path)
    chk.add_argument("--mode", choices=("declared", "required"), default="declared")
    chk.add_argument("--env-file", action="append", default=[], type=Path)
    chk.add_argument("--token-file", type=Path,
                     help="the key the catalog was captured with, so its tool filters are checked")
    args = parser.parse_args(argv)
    if args.cmd == "capture":
        token = args.token_file.read_text().strip() if args.token_file else None
        catalog, failed = capture(args.url, token)
        args.out.write_text(json.dumps(catalog, indent=1, sort_keys=True))
        print(f"captured {sum(map(len, catalog.values()))} tools from {len(catalog)} servers"
              f"; {failed} failed to list")
        # The catalog is still written so `check` can name the gaps.
        return 1 if failed else 0
    try:
        config = yaml.safe_load(args.config.read_text()) or {}
        catalog = json.loads(args.catalog.read_text())
        found, stats = problems(config, catalog, args.mode, env_override(config, args.env_file))
        token = args.token_file.read_text().strip() if args.token_file else None
        found = profile_problems(config) + key_problems(config, token) + found
    except Unverifiable as err:
        print(err)
        return 1
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as err:
        print(f"unreadable input: {err}", file=sys.stderr)
        return 2
    print(json.dumps(stats, sort_keys=True))
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
