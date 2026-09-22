#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline stdio MCP peer for the NFR.DEMO.1 scenario-2 recording.

A sibling of demo_era_peer.py with the two properties the reconnectable-task
scenario needs and that fixture does not have:

1. A tool call takes DELAY_SECS, so a task is genuinely still in flight when
   the recording kills the gateway.
2. Every tool call appends one line to SUBMISSIONS_FILE before sleeping, so
   the submission count survives the peer being killed with its parent.

Point 2 is the scenario's negative control. The design's broken build "shows
the peer's submission counter at two -- a silently replayed side effect, the
one outcome LIFECYCLE.4 forbids", so the count has to be readable from outside
the process that is about to be killed. It is ported from the accounting the
in-process helper already keeps (tests/task_upstream_recovery/helper.rs:77,
`submissions`); nothing else from that helper is reimplemented here.

    demo_task_peer.py NAME SUBMISSIONS_FILE DELAY_SECS
"""
import json
import sys
import time

PROTOCOL_VERSION = "2025-06-18"


def main():
    name, submissions_file, delay = sys.argv[1], sys.argv[2], float(sys.argv[3])
    tool = f"{name}_ping"
    tools = [
        {
            "name": tool,
            "description": f"Task demo fixture tool served by {name}.",
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
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": "1.0.0"},
            })
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            reply(req_id, {"tools": tools})
        elif method == "tools/call":
            args = (req.get("params") or {}).get("arguments") or {}
            text = args.get("text", "")
            # Recorded BEFORE the work, not after: a replay that is killed
            # before it finishes still counts as a second submission, which is
            # exactly the side effect the control is looking for.
            with open(submissions_file, "a", encoding="utf-8") as handle:
                handle.write(f"{time.time()} {text}\n")
            time.sleep(delay)
            reply(req_id, {"content": [
                {"type": "text", "text": f"{name} answered: {text}"}
            ]})
        elif req_id is not None:
            reply(req_id, {})


if __name__ == "__main__":
    main()
