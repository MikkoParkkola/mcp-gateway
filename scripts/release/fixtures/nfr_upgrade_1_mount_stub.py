#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Deterministic, offline stdio MCP backend used only by
scripts/release/nfr_upgrade_1_rehearsal.sh.

Speaks the minimum subset of MCP over newline-delimited JSON-RPC needed to be
mounted as a gateway "backend": initialize, notifications/initialized
(no reply), tools/list (one tool: echo), tools/call. No network, no
dependencies beyond the stdlib, so the rehearsal's "active caller can still
invoke a mounted tool" check has nothing external to flake on.
"""
import json
import sys


def reply(id_, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": id_, "result": result}) + "\n")
    sys.stdout.flush()


TOOLS = [
    {
        "name": "echo",
        "description": "Echoes the given text back. Rehearsal fixture only.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }
]


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            reply(
                req_id,
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "nfr-upgrade-1-mount-stub", "version": "1.0.0"},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            reply(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            args = (req.get("params") or {}).get("arguments") or {}
            text = args.get("text", "")
            reply(
                req_id,
                {"content": [{"type": "text", "text": f"rehearsal-echo: {text}"}]},
            )
        elif req_id is not None:
            reply(req_id, {})


if __name__ == "__main__":
    main()
