#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline stdio MCP peer for the NFR.DEMO.1 scenario-1 recording.

Ported from the shell peer the era-observability test already scripts
(tests/nfr_obs_3_era_observability.rs:133-155): a recorder, not a participant.
No era logic lives here -- it answers the same canned frames whatever the
gateway believes, which is what keeps the classification under test.

    demo_era_peer.py NAME PROTOCOL_VERSION {modern|not_modern}

`modern` answers server/discover with a document naming 2026-07-28, so the
gateway must classify the peer era=modern era_evidence=discover_modern.
`not_modern` answers, but names no modern revision, so the same probe must
classify it era=legacy era_evidence=discover_not_modern.
"""
import json
import sys

MODERN_VERSIONS = ["2026-07-28", "2025-11-25"]
LEGACY_VERSIONS = ["2025-06-18", "2025-03-26"]


def main():
    name, version, arm = sys.argv[1], sys.argv[2], sys.argv[3]
    tool = f"{name}_ping"
    tools = [
        {
            "name": tool,
            "description": f"Era demo fixture tool served by {name}.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        }
    ]

    def reply(id_, result):
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": id_, "result": result}) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method, req_id = req.get("method"), req.get("id")
        if method == "initialize":
            reply(req_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            continue
        elif method == "server/discover":
            versions = MODERN_VERSIONS if arm == "modern" else LEGACY_VERSIONS
            reply(req_id, {"capabilities": {}, "supportedVersions": versions})
        elif method == "tools/list":
            reply(req_id, {"tools": tools})
        elif method == "tools/call":
            args = (req.get("params") or {}).get("arguments") or {}
            reply(req_id, {"content": [
                {"type": "text", "text": f"{name} answered: {args.get('text', '')}"}
            ]})
        elif req_id is not None:
            reply(req_id, {})


if __name__ == "__main__":
    main()
