#!/usr/bin/env python3
"""Deterministic stdio MCP backend for the NFR.WORKLOAD.1 harness.

Frozen fixture. One tool, one fixed argument, one fixed payload, and no
per-call I/O of any kind -- nothing is logged, opened or flushed to disk
inside a tools/call, so the measured latency is gateway time and not fixture
time. Any change to this file changes the workload and voids a comparison
that spans the change.

Era control: --protocol-version pins what the backend reports at
initialize. "echo" replies with whatever the gateway asked for, which is what
the legacy and modern cells use. A fixed value is what the mixed-era cell
uses, so the backend deliberately disagrees with the client.
"""

from __future__ import annotations

import argparse
import json
import sys

LEGACY_PROTOCOL = "2025-06-18"
MODERN_PROTOCOL = "2026-07-28"

TOOL_NAME = "workload_probe"
EXPECTED_ARGS = {"case_reference": "042"}
# The semantic assertion in k6_workload.js matches this exact string.
EXPECTED_TEXT = "WORKLOAD_OK case=042 bundle=deterministic"

TOOL_SPEC = {
    "name": TOOL_NAME,
    "description": "Return the fixed evidence bundle for the pinned case.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "case_reference": {
                "type": "string",
                "description": "Three-digit case number; the fixture pins 042.",
            }
        },
        "required": ["case_reference"],
        "additionalProperties": False,
    },
}


def result(request_id, value):
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error(request_id, code, message):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class Backend:
    def __init__(self, protocol_version: str) -> None:
        self.protocol_version = protocol_version

    def negotiated(self, requested: str) -> str:
        if self.protocol_version == "echo":
            return requested or LEGACY_PROTOCOL
        return self.protocol_version

    def handle(self, message):
        method = message.get("method")
        request_id = message.get("id")

        # Notifications carry no id and take no response.
        if request_id is None:
            return None

        if method == "initialize":
            requested = str(
                (message.get("params") or {}).get("protocolVersion") or ""
            )
            return result(
                request_id,
                {
                    "protocolVersion": self.negotiated(requested),
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "nfr-workload-1-fixture",
                        "version": "1",
                    },
                },
            )

        if method == "tools/list":
            return result(request_id, {"tools": [TOOL_SPEC]})

        if method != "tools/call":
            return error(request_id, -32601, "unsupported method")

        params = message.get("params") or {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}

        if name != TOOL_NAME:
            return error(request_id, -32602, "tool not recognised by the fixture")
        if arguments != EXPECTED_ARGS:
            # Deterministic: a drifted argument must fail loudly, not degrade.
            return error(request_id, -32602, "arguments did not match the pin")

        return result(
            request_id,
            {"content": [{"type": "text", "text": EXPECTED_TEXT}], "isError": False},
        )

    def run(self) -> None:
        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                message = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            response = self.handle(message)
            if response is not None:
                print(json.dumps(response, separators=(",", ":")), flush=True)


def self_check() -> None:
    echo = Backend("echo")
    pinned = Backend(LEGACY_PROTOCOL)

    init = echo.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": MODERN_PROTOCOL}}
    )
    assert init["result"]["protocolVersion"] == MODERN_PROTOCOL, init

    init = pinned.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": MODERN_PROTOCOL}}
    )
    assert init["result"]["protocolVersion"] == LEGACY_PROTOCOL, init

    listed = echo.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [t["name"] for t in listed["result"]["tools"]] == [TOOL_NAME], listed

    ok = echo.handle(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": TOOL_NAME, "arguments": EXPECTED_ARGS}}
    )
    assert ok["result"]["content"][0]["text"] == EXPECTED_TEXT, ok
    assert ok["result"]["isError"] is False, ok

    bad = echo.handle(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": TOOL_NAME, "arguments": {"case_reference": "999"}}}
    )
    assert "error" in bad, bad

    absent = echo.handle(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "other_tool", "arguments": EXPECTED_ARGS}}
    )
    assert absent["error"]["code"] == -32602, absent

    note = echo.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert note is None, note

    print("mcp_backend self-check OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protocol-version",
        default="echo",
        help='"echo", or a pinned version such as 2025-06-18 / 2026-07-28.',
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="Run the built-in assertions and exit.",
    )
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    Backend(args.protocol_version).run()


if __name__ == "__main__":
    main()
