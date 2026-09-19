#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline stdio MCP peer that fails its tool calls while a marker file exists.

    demo_flaky_peer.py FAIL_MARKER_PATH

The upgrade rehearsal's mount stub with one addition (the design's scenario-5
"fail-N-then-succeed mode", expressed as a file the driver can create and
delete, so recovery is something the operator does on camera rather than a
timer the recording waits out). Health is a property of the peer; the kill
switch and its release are properties of the gateway.
"""
import json
import os
import sys

TOOLS = [{
    "name": "budget_ping",
    "description": "Answers while healthy, errors while the fail marker exists.",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
}]


def main():
    marker = sys.argv[1]

    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
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
            send({"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "demo-flaky-peer", "version": "1.0.0"}}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            if os.path.exists(marker):
                send({"jsonrpc": "2.0", "id": req_id, "error": {
                    "code": -32000, "message": "upstream unavailable (demo fault injection)"}})
            else:
                send({"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": "budget_ping ok"}]}})
        elif req_id is not None:
            send({"jsonrpc": "2.0", "id": req_id, "result": {}})


if __name__ == "__main__":
    main()
