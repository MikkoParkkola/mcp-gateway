#!/usr/bin/env python3
"""Isolated MCP server for the MIK-6977 live-agent benchmark."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


def tool_name(index: int) -> str:
    return f"archive_case_{index:03d}"


def direct_tools(count: int) -> list[dict[str, Any]]:
    return [
        {
            "name": tool_name(index),
            "description": (
                f"Retrieve the archived compliance evidence bundle for case {index:03d}. "
                "Use only when the requested case number matches exactly."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_reference": {
                        "type": "string",
                        "description": "The three-digit case number requested by the user.",
                    }
                },
                "required": ["case_reference"],
                "additionalProperties": False,
            },
        }
        for index in range(count)
    ]


def meta_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "gateway_search_tools",
            "description": "Search the permitted tool catalog by the user's requested capability.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "name": "gateway_invoke",
            "description": "Invoke one exact tool returned by gateway_search_tools.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object"},
                },
                "required": ["tool_name", "arguments"],
                "additionalProperties": False,
            },
        },
    ]


class Server:
    def __init__(
        self,
        mode: str,
        count: int,
        expected_index: int,
        trial_id: str,
        log_path: Path,
    ) -> None:
        self.mode = mode
        self.count = count
        self.expected_index = expected_index
        self.expected_tool = tool_name(expected_index)
        self.trial_id = trial_id
        self.log_path = log_path

    def log(self, event: dict[str, Any]) -> None:
        event = {"at_unix_s": time.time(), **event}
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def result(self, request_id: Any, value: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": value}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            return None
        if method == "initialize":
            return self.result(
                request_id,
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "mik-6977-live-benchmark", "version": "1"},
                },
            )
        if method == "ping":
            return self.result(request_id, {})
        if method == "tools/list":
            tools = direct_tools(self.count) if self.mode == "direct" else meta_tools()
            self.log({"event": "tools_list", "mode": self.mode, "count": len(tools)})
            return self.result(request_id, {"tools": tools})
        if method != "tools/call":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unsupported method: {method}"},
            }

        params = message.get("params") or {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        selected = name
        if self.mode == "meta" and name == "gateway_invoke":
            selected = str(arguments.get("tool_name") or "")
        correct = selected == self.expected_tool
        self.log(
            {
                "event": "tool_call",
                "mode": self.mode,
                "name": name,
                "selected_tool": selected,
                "arguments": arguments,
                "correct": correct,
            }
        )

        if self.mode == "meta" and name == "gateway_search_tools":
            query = str(arguments.get("query") or "")
            requested = re.search(r"\b(\d{1,3})\b", query)
            matched_index = (
                int(requested.group(1)) if requested else self.expected_index
            )
            indices = [matched_index]
            indices.extend(
                index
                for index in range(
                    max(0, matched_index - 2), min(self.count, matched_index + 3)
                )
                if index != matched_index
            )
            payload = {
                "matches": [
                    {
                        "name": tool_name(index),
                        "description": f"Archived compliance evidence for case {index:03d}",
                    }
                    for index in indices[:5]
                ]
            }
            text = json.dumps(payload, sort_keys=True)
        elif correct:
            text = f"BENCH_OK_{self.trial_id}: evidence bundle {self.expected_index:03d} retrieved"
        else:
            text = (
                f"BENCH_WRONG_{self.trial_id}: selected {selected or '<none>'}; "
                f"expected {self.expected_tool}"
            )
        return self.result(
            request_id,
            {"content": [{"type": "text", "text": text}], "isError": False},
        )

    def run(self) -> None:
        for raw_line in sys.stdin:
            try:
                message = json.loads(raw_line)
                response = self.handle(message)
            except Exception as error:  # keep the benchmark protocol observable
                self.log({"event": "server_error", "error": repr(error)})
                continue
            if response is not None:
                print(json.dumps(response, separators=(",", ":")), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("direct", "meta"), required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--expected-index", type=int, required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    if args.count < 1 or not 0 <= args.expected_index < args.count:
        parser.error("expected-index must be within the generated catalog")
    Server(args.mode, args.count, args.expected_index, args.trial_id, args.log).run()


if __name__ == "__main__":
    main()
