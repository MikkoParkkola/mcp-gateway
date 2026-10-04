#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Stdio MCP server double for MCP capabilities (MIK-7782). Standard library only.

Tools:
  echo          structuredContent {name, arguments, pid, cwd, home}
  import_binary structuredContent {program_name: "prog-" + basename(binary_path)}
  fail          isError true with a text block
  flood         answers with one 20 MiB line and no newline until the end
  grandchild    starts a sleeping grandchild and returns its pid
"""
import json
import os
import subprocess
import sys

TOOLS = ["echo", "import_binary", "fail", "flood", "grandchild", "list_project_binaries"]
POLLS = {"n": 0}


def test_values():
    # Test-owned names only: run by hand, this must not print a real environment.
    return {k: v for k, v in os.environ.items() if k.startswith("CAP_EXEC_TEST_")}


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def result(req_id, value):
    send({"jsonrpc": "2.0", "id": req_id, "result": value})


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method, req_id = msg.get("method"), msg.get("id")
    if req_id is None:
        continue  # notification
    if method == "initialize":
        version = msg.get("params", {}).get("protocolVersion", "2025-06-18")
        result(req_id, {"protocolVersion": version, "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake-mcp", "version": "0"}})
    elif method == "tools/list":
        result(req_id, {"tools": [{"name": t, "inputSchema": {"type": "object"}} for t in TOOLS]})
    elif method == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        if name == "echo":
            result(req_id, {"content": [], "structuredContent": {
                "name": name, "arguments": args, "pid": os.getpid(), "cwd": os.getcwd(),
                "home": os.environ.get("HOME", ""), "test_values": test_values()}})
        elif name == "import_binary":
            base = os.path.basename(args.get("binary_path", ""))
            result(req_id, {"content": [], "structuredContent": {"program_name": "prog-" + base}})
        elif name == "list_project_binaries":
            # Analysis "finishes" on the third poll; the first two answer an error
            # for an absent program, as the real server does.
            if args.get("expect") == "die":
                os._exit(0)
            POLLS["n"] += 1
            if POLLS["n"] < 2:
                result(req_id, {"isError": True, "content": [{"type": "text", "text": "no such binary"}]})
            else:
                done = POLLS["n"] >= 4
                result(req_id, {"content": [], "structuredContent": {"programs": [
                    {"name": "other", "file_path": "/other", "analysis_complete": True},
                    {"name": "prog-x", "file_path": args.get("expect", ""), "analysis_complete": done,
                     "test_values": test_values()}]}})
        elif name == "fail":
            result(req_id, {"isError": True, "content": [{"type": "text", "text": "tool said no"}]})
        elif name == "flood":
            sys.stdout.write("x" * (20 * 1024 * 1024))
            sys.stdout.write("\n")
            sys.stdout.flush()
        elif name == "grandchild":
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
            result(req_id, {"content": [], "structuredContent": {"pid": child.pid}})
        else:
            send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "unknown tool"}})
    else:
        send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "no such method"}})
